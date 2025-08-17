(ns auth-server
  (:require [ring.adapter.jetty :as jetty]
            [reitit.ring :as ring]
            [reitit.coercion.spec]
            [reitit.ring.coercion :as coercion]
            [reitit.ring.middleware.muuntaja :as muuntaja]
            [reitit.ring.middleware.exception :as exception]
            [reitit.ring.middleware.parameters :as parameters]
            [muuntaja.core :as m]
            [ring.middleware.cors :refer [wrap-cors]]
            [environ.core :refer [env]]
            [next.jdbc :as jdbc]
            [hikari-cp.core :as hikari]
            [taoensso.carmine :as car :refer [wcar]]
            [buddy.sign.jwt :as jwt]
            [buddy.hashers :as hashers]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [cheshire.core :as cheshire]
            [clojure.java.io :as io])
  (:import [com.zaxxer.hikari HikariDataSource]
           [com.nulabinc.zxcvbn Zxcvbn])
  (:gen-class))

;; Configuration
(def config
  (let [cfg {:port (or (some-> (env :port) Integer/parseInt) 8000)
             :jwt-secret (env :jwt-secret)
             :token-expiry (or (some-> (env :token-expiry) Integer/parseInt) 3600)
             :refresh-token-expiry (or (some-> (env :refresh-token-expiry) Integer/parseInt) 604800)
             :password-reset-expiry (or (some-> (env :password-reset-expiry) Integer/parseInt) 86400)
             :bcrypt-rounds (or (some-> (env :bcrypt-rounds) Integer/parseInt) 12)
             :max-request-size (or (some-> (env :max-request-size) Integer/parseInt) 10240)
             :rate-limit-requests (or (some-> (env :rate-limit-requests) Integer/parseInt) 100)
             :rate-limit-window (or (some-> (env :rate-limit-window) Integer/parseInt) 60000)
             :rate-limit-login-attempts (or (some-> (env :rate-limit-login-attempts) Integer/parseInt) 5)
             :allowed-origins (set (str/split (or (env :allowed-origins) "http://localhost:3000") #","))
             :rate-limit-cleanup-interval (or (some-> (env :rate-limit-cleanup-interval) Integer/parseInt) 60000)
             :blacklist-cleanup-interval (or (some-> (env :blacklist-cleanup-interval) Integer/parseInt) 3600000)
             :db-user (env :db-user)
             :db-password (env :db-password)
             :db-name (env :db-name)
             :db-host (env :db-host)
             :db-port (or (some-> (env :db-port) Integer/parseInt) 5432)
             :db-retries (or (some-> (env :db-retries) Integer/parseInt) 3)
             :db-pool-size (or (some-> (env :db-pool-size) Integer/parseInt) 20)
             :csrf-token-expiry (or (some-> (env :csrf-token-expiry) Integer/parseInt) 3600)
             :redis-host (or (env :redis-host) "localhost")
             :redis-port (or (some-> (env :redis-port) Integer/parseInt) 6379)
             :redis-retries (or (some-> (env :redis-retries) Integer/parseInt) 3)
             :common-passwords (set (str/split (or (env :common-passwords) "password123,admin123,12345678,qwerty123") #","))}]
    (when (or (str/blank? (:jwt-secret cfg)) (str/blank? (:db-user cfg)) (str/blank? (:db-password cfg)) (str/blank? (:db-name cfg)) (str/blank? (:db-host cfg)))
      (throw (ex-info "Missing required environment variables" {})))
    cfg))

;; Database and Redis
(def ds (atom nil))
(def redis-conn {:pool {} :spec {:host (:redis-host config) :port (:redis-port config)}})
(defmacro wcar* [& body] `(car/wcar redis-conn ~@body))

(def store-type (atom :redis))
(def in-memory-store (atom {}))

(defn current-ms [] (System/currentTimeMillis))

(defn my-incr [key ttl-ms]
  (if (= @store-type :redis)
    (let [count (wcar* (car/incr key))]
      (wcar* (car/pexpire key ttl-ms))
      count)
    (let [new-store (swap! in-memory-store (fn [store]
                                              (let [m (get store key)
                                                    curr (current-ms)
                                                    expired? (or (nil? m) (<= (:expire m) curr))
                                                    new-v (if expired? 1 (inc (:value m 0)))
                                                    new-exp (if expired? (+ curr ttl-ms) (:expire m))]
                                                (assoc store key {:value new-v :expire new-exp}))))]
      (get-in new-store [key :value]))))

(defn my-get [key]
  (if (= @store-type :redis)
    (wcar* (car/get key))
    (let [curr (current-ms)
          m (get @in-memory-store key)]
      (if (and m (> (:expire m) curr))
        (:value m)
        (do (swap! in-memory-store dissoc key) nil)))))

(defn my-set-ex [key val sec]
  (if (= @store-type :redis)
    (wcar* (car/set key val :ex sec))
    (let [ms (* sec 1000)
          exp (+ (current-ms) ms)]
      (swap! in-memory-store assoc key {:value val :expire exp}))))

(defn cleanup-rate-limits []
  (if (= @store-type :redis)
    (doseq [k (wcar* (car/keys "rate:*"))]
      (when (<= (wcar* (car/pttl k)) 0)
        (wcar* (car/del k))))
    (swap! in-memory-store (fn [store]
                             (into {} (filter (fn [[k m]]
                                                (and (.startsWith k "rate:")
                                                     (> (:expire m) (current-ms))))
                                              store))))))

(defn cleanup-blacklist []
  (if (= @store-type :redis)
    (doseq [k (wcar* (car/keys "blacklist:*"))]
      (when (<= (wcar* (car/ttl k)) 0)
        (wcar* (car/del k))))
    (swap! in-memory-store (fn [store]
                             (into {} (filter (fn [[k m]]
                                                (and (.startsWith k "blacklist:")
                                                     (> (:expire m) (current-ms))))
                                              store))))))

(defn create-datasource []
  (hikari/make-datasource {:adapter "postgresql"
                           :username (:db-user config)
                           :password (:db-password config)
                           :database-name (:db-name config)
                           :server-name (:db-host config)
                           :port-number (:db-port config)
                           :maximum-pool-size (:db-pool-size config)}))

(defn init-db []
  (loop [attempt 1]
    (try
      (reset! ds (create-datasource))
      (jdbc/execute! @ds ["SELECT 1"])
      (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP, token_version BIGINT DEFAULT 0);"])
      (jdbc/execute! @ds ["CREATE UNIQUE INDEX IF NOT EXISTS users_lower_idx ON users (LOWER(username));"])
      (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);"])
      (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS csrf_tokens (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), action VARCHAR(50) NOT NULL, expires_at TIMESTAMP NOT NULL);"])
      (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS csrf_tokens_expires_idx ON csrf_tokens (expires_at);"])
      (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS password_resets (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), expires_at TIMESTAMP NOT NULL);"])
      (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS password_resets_expires_idx ON password_resets (expires_at);"])
      (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, action VARCHAR(50) NOT NULL, username VARCHAR(255), ip VARCHAR(45), timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, details JSONB);"])
      (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS audit_log_details_idx ON audit_log USING GIN (details);"])
      (catch Exception e
        (if (< attempt (:db-retries config))
          (do (Thread/sleep 5000) (recur (inc attempt)))
          (throw e))))))

(defn init-redis []
  (loop [attempt 1]
    (try
      (wcar* (car/ping))
      (catch Exception e
        (if (< attempt (:redis-retries config))
          (do (Thread/sleep 5000) (recur (inc attempt)))
          (do (log/warn "Redis unavailable, using in-memory fallback for rate limiting and blacklisting")
              (reset! store-type :memory)))))))

;; Utilities
(defn sanitize [s]
  (str/escape s {\< "&lt;" \> "&gt;" \& "&amp;" \" "&quot;" \' "&#39;"}))

(defn valid-username? [u]
  (and u (re-matches #"^[a-zA-Z0-9_-]{3,30}$" u)))

(defn valid-email? [e]
  (and e (re-matches #"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" e)))

(defn valid-password? [p]
  (let [z (Zxcvbn.)
        strength (.measure z p)
        score (.getScore strength)]
    (and p (>= (count p) 8)
         (re-find #"[A-Z]" p)
         (re-find #"\d" p)
         (re-find #"[!@#$%^&*()_+-=]" p)
         (not (contains? (:common-passwords config) (str/lower-case p)))
         (>= score 2))))

(defn sign-token [claims expiry]
  (jwt/sign claims (:jwt-secret config) {:alg :hs512 :exp (+ (quot (System/currentTimeMillis) 1000) expiry)}))

(defn unsign-token [token]
  (try
    (jwt/unsign token (:jwt-secret config) {:alg :hs512})
    (catch Exception _ nil)))

(defn generate-csrf [username action]
  (let [token (str (java.util.UUID/randomUUID))
        expires (java.sql.Timestamp. (+ (System/currentTimeMillis) (* (:csrf-token-expiry config) 1000)))]
    (jdbc/execute! @ds ["INSERT INTO csrf_tokens (token, username, action, expires_at) VALUES (?, ?, ?, ?)" token username action expires])
    token))

(defn validate-csrf [token username action]
  (let [row (jdbc/execute-one! @ds ["SELECT * FROM csrf_tokens WHERE token = ? AND (username = ? OR username IS NULL) AND action = ? AND expires_at > NOW()" token username action])]
    (when row
      (jdbc/execute! @ds ["DELETE FROM csrf_tokens WHERE token = ?" token])
      true)))

(defn audit [action username ip details]
  (jdbc/execute! @ds ["INSERT INTO audit_log (action, username, ip, details) VALUES (?, ?, ?, ?::jsonb)" action username ip (cheshire/generate-string details)]))

(defn get-db-token-version [username]
  (:token_version (jdbc/execute-one! @ds ["SELECT token_version FROM users WHERE username = ?" username])))

(defn user-exists? [username email]
  (boolean (jdbc/execute-one! @ds ["SELECT 1 FROM users WHERE LOWER(username) = LOWER(?) OR email = ?" username email])))

;; Middleware
(defn rate-limit-middleware [handler]
  (fn [req]
    (let [ip (:remote-addr req)
          path (:uri req)
          bucket (quot (System/currentTimeMillis) (:rate-limit-window config))
          key (str "rate:ip:" ip ":" path ":" bucket)
          ttl (- (:rate-limit-window config) (mod (System/currentTimeMillis) (:rate-limit-window config)))
          count (my-incr key ttl)]
      (if (> count (:rate-limit-requests config))
        {:status 429 :body {:error "Rate limit exceeded"}}
        (handler req)))))

(defn secure-headers-middleware [handler]
  (fn [req]
    (let [resp (handler req)]
      (-> resp
          (assoc-in [:headers "Strict-Transport-Security"] "max-age=31536000; includeSubDomains")
          (assoc-in [:headers "Content-Security-Policy"] "default-src 'self'; script-src 'self'; object-src 'none'")
          (assoc-in [:headers "X-Content-Type-Options"] "nosniff")
          (assoc-in [:headers "X-Frame-Options"] "DENY")))))

(defn logger-middleware [handler]
  (fn [req]
    (let [start (System/currentTimeMillis)
          resp (handler req)
          duration (- (System/currentTimeMillis) start)
          username (get-in req [:identity :username])]
      (log/info {:timestamp (java.time.Instant/now)
                 :level "INFO"
                 :message "Request handled"
                 :method (:request-method req)
                 :path (:uri req)
                 :ip (:remote-addr req)
                 :userAgent (get-in req [:headers "user-agent"])
                 :duration duration
                 :status (:status resp)
                 :username username
                 :requestId (str (java.util.UUID/randomUUID))})
      resp)))

(defn auth-middleware [handler]
  (fn [req]
    (let [auth (get-in req [:headers "authorization"])
          token (when (and auth (str/starts-with? (str/lower-case auth) "bearer ")) (subs auth 7))]
      (if-not token
        {:status 401 :body {:error "Missing token"}}
        (if (my-get (str "blacklist:" token))
          {:status 401 :body {:error "Blacklisted token"}}
          (let [claims (unsign-token token)]
            (if-not claims
              {:status 401 :body {:error "Invalid token"}}
              (let [{:keys [username token_version]} claims
                    db-v (get-db-token-version username)]
                (if (and db-v (= token_version db-v))
                  (handler (assoc req :identity {:username username} :claims claims))
                  {:status 401 :body {:error "Invalid token version"}})))))))))

;; Handlers
(defn csrf-handler [req]
  (let [action (get-in req [:path-params :action])
        username (get-in req [:identity :username])]
    {:status 200 :body {:csrfToken (generate-csrf username action)}}))

(defn register-handler [req]
  (let [body (:body req)
        username (sanitize (get body "username"))
        password (get body "password")
        email (sanitize (get body "email"))
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)]
    (cond
      (not (and (valid-username? username) (valid-password? password) (valid-email? email)))
      {:status 400 :body {:error "Invalid input"}}

      (not (validate-csrf csrf-token nil "register"))
      {:status 401 :body {:error "Invalid/missing CSRF token"}}

      (user-exists? username email)
      {:status 409 :body {:error "Username or email already exists"}}

      :else
      (let [hashed (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
        (jdbc/with-transaction [tx @ds]
          (jdbc/execute! tx ["INSERT INTO users (username, password, email) VALUES (?, ?, ?)" username hashed email])
          (audit "register" username ip {:email email}))
        {:status 201 :body {:message "User registered successfully"}}))))

(defn login-handler [req]
  (let [body (:body req)
        username (get body "username")
        password (get body "password")
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)
        bucket (quot (System/currentTimeMillis) (:rate-limit-window config))
        rate-key (str "rate:login:" (str/lower-case username) ":" bucket)
        ttl (- (:rate-limit-window config) (mod (System/currentTimeMillis) (:rate-limit-window config)))
        count (my-incr rate-key ttl)]
    (cond
      (> count (:rate-limit-login-attempts config))
      {:status 429 :body {:error "Rate limit exceeded"}}

      (not (validate-csrf csrf-token nil "login"))
      {:status 401 :body {:error "Invalid/missing CSRF token"}}

      :else
      (let [user (jdbc/execute-one! @ds ["SELECT * FROM users WHERE LOWER(username) = LOWER(?)" username])]
        (if-not user
          (do (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})
              (Thread/sleep (rand-int 500))
              (audit "login_failed" username ip {})
              {:status 401 :body {:error "Invalid credentials"}})
          (if-not (hashers/check password (:password user))
            (do (Thread/sleep (rand-int 500))
                (audit "login_failed" username ip {})
                {:status 401 :body {:error "Invalid credentials"}})
            (let [db-v (:token_version user)
                  access (sign-token {:username username :token_version db-v} (:token-expiry config))
                  refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
                  new-csrf (generate-csrf username "post-login")]
              (jdbc/execute! @ds ["UPDATE users SET last_login = NOW() WHERE username = ?" username])
              (audit "login_success" username ip {})
              {:status 200 :body {:token access :refreshToken refresh :csrfToken new-csrf}})))))))

(defn refresh-handler [req]
  (let [body (:body req)
        refresh-token (get body "refreshToken")
        csrf-token (get body "csrfToken")]
    (cond
      (not refresh-token)
      {:status 400 :body {:error "Invalid input"}}

      :else
      (let [claims (unsign-token refresh-token)]
        (cond
          (not claims)
          {:status 401 :body {:error "Invalid/expired refresh token"}}

          (my-get (str "blacklist:" refresh-token))
          {:status 401 :body {:error "Blacklisted token"}}

          :else
          (let [username (:username claims)
                db-v (get-db-token-version username)]
            (cond
              (not (= (:token_version claims) db-v))
              {:status 401 :body {:error "Invalid token version"}}

              (not (validate-csrf csrf-token username "refresh"))
              {:status 401 :body {:error "Invalid/missing CSRF token"}}

              :else
              (let [new-access (sign-token {:username username :token_version db-v} (:token-expiry config))
                    new-refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
                    ttl (- (:exp claims) (quot (System/currentTimeMillis) 1000))]
                (my-set-ex (str "blacklist:" refresh-token) "1" ttl)
                {:status 200 :body {:token new-access :refreshToken new-refresh}}))))))))

(defn logout-handler [req]
  (let [csrf (get-in req [:headers "x-csrf-token"])
        username (get-in req [:identity :username])
        claims (:claims req)
        token (subs (get-in req [:headers "authorization"]) 7)
        ip (:remote-addr req)]
    (cond
      (not (validate-csrf csrf username "logout"))
      {:status 401 :body {:error "Invalid/missing CSRF token"}}

      :else
      (do
        (jdbc/execute! @ds ["UPDATE users SET token_version = token_version + 1 WHERE username = ?" username])
        (let [ttl (- (:exp claims) (quot (System/currentTimeMillis) 1000))]
          (my-set-ex (str "blacklist:" token) "1" ttl))
        (audit "logout" username ip {})
        {:status 200 :body {:message "Logged out successfully"}}))))

(defn forgot-handler [req]
  (let [body (:body req)
        email (sanitize (get body "email"))
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)]
    (cond
      (not (valid-email? email))
      {:status 400 :body {:error "Invalid input"}}

      (not (validate-csrf csrf-token nil "forgot-password"))
      {:status 401 :body {:error "Invalid/missing CSRF token"}}

      :else
      (let [user (jdbc/execute-one! @ds ["SELECT username FROM users WHERE email = ?" email])]
        (if user
          (let [token (str (java.util.UUID/randomUUID))
                expires (java.sql.Timestamp. (+ (System/currentTimeMillis) (* (:password-reset-expiry config) 1000)))]
            (jdbc/execute! @ds ["INSERT INTO password_resets (token, username, expires_at) VALUES (?, ?, ?)" token (:username user) expires])
            (audit "password_reset_requested" (:username user) ip {:email email})
            {:status 200 :body {:message "If the email exists, a reset link has been sent" :resetToken token}})  ;; For demo
          (do
            (str (java.util.UUID/randomUUID))  ;; Simulate
            {:status 200 :body {:message "If the email exists, a reset link has been sent"}}))))))

(defn reset-handler [req]
  (let [body (:body req)
        token (get body "token")
        new-password (get body "newPassword")
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)]
    (cond
      (not (and token (valid-password? new-password)))
      {:status 400 :body {:error "Invalid input"}}

      :else
      (let [reset (jdbc/execute-one! @ds ["SELECT username FROM password_resets WHERE token = ? AND expires_at > NOW()" token])]
        (cond
          (not reset)
          {:status 401 :body {:error "Invalid/expired reset token"}}

          (not (validate-csrf csrf-token (:username reset) "reset-password"))
          {:status 401 :body {:error "Invalid/missing CSRF token"}}

          :else
          (let [hashed (hashers/derive new-password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
            (jdbc/with-transaction [tx @ds]
              (jdbc/execute! tx ["UPDATE users SET password = ?, token_version = token_version + 1 WHERE username = ?" hashed (:username reset)])
              (jdbc/execute! tx ["DELETE FROM password_resets WHERE token = ?" token])
              (audit "password_reset" (:username reset) ip {}))
            {:status 200 :body {:message "Password reset successfully"}}))))))

(defn health-handler [_]
  (let [db-ok (try (jdbc/execute! @ds ["SELECT 1"]) true (catch Exception _ false))
        redis-ok (try (when (= @store-type :redis) (wcar* (car/ping))) true (catch Exception _ false))
        jwt-ok (let [test-claims {:test 1}
                     test-token (sign-token test-claims 10)
                     unsign-claims (unsign-token test-token)]
                 (and test-token unsign-claims (= (:test unsign-claims) 1)))
        rate-limit-size (if (= @store-type :redis)
                          (count (wcar* (car/keys "rate:*")))
                          (count (filter #(.startsWith ^String % "rate:") (keys @in-memory-store))))
        pool-stats (let [hikari-pool (.getHikariPoolMXBean ^HikariDataSource @ds)]
                     (.getTotalConnections hikari-pool))]
    (if (and db-ok jwt-ok)
      {:status 200 :body {:status "ok"
                          :components {:database (if db-ok "ok" "error")
                                       :redis (if redis-ok "ok" "degraded")
                                       :jwt (if jwt-ok "ok" "error")
                                       :rateLimitSize rate-limit-size
                                       :poolStats pool-stats}}}
      {:status 503 :body {:status "error"
                          :components {:database (if db-ok "ok" "error")
                                       :redis (if redis-ok "ok" "degraded")
                                       :jwt (if jwt-ok "ok" "error")
                                       :rateLimitSize rate-limit-size
                                       :poolStats pool-stats}}})))

;; App
(def muuntaja (m/create m/defaults))

(def app
  (ring/ring-handler
    (ring/router
      [["/csrf/{action}" {:get csrf-handler}]
       ["/register" {:post register-handler}]
       ["/login" {:post login-handler}]
       ["/refresh" {:post refresh-handler}]
       ["/validate" {:get {:middleware [auth-middleware]
                           :handler (fn [req] {:status 200 :body {:username (get-in req [:identity :username])}})}}]
       ["/logout" {:post {:middleware [auth-middleware]
                          :handler logout-handler}}]
       ["/forgot-password" {:post forgot-handler}]
       ["/reset-password" {:post reset-handler}]
       ["/health" {:get health-handler}]]
      {:data {:muuntaja muuntaja
              :coercion reitit.coercion.spec/coercion
              :middleware [parameters/parameters-middleware
                           muuntaja/format-middleware
                           exception/exception-middleware
                           rate-limit-middleware
                           secure-headers-middleware
                           logger-middleware
                           (wrap-cors :access-control-allow-origin (:allowed-origins config)
                                      :access-control-allow-methods [:get :post :options]
                                      :access-control-allow-headers ["Content-Type" "Authorization" "X-CSRF-Token"])]}})
    (ring/create-default-handler {:not-found (constantly {:status 404 :body {:error "Not found"}})})))

;; Server
(def server (atom nil))
(def cleanup-rate-thread (atom nil))
(def cleanup-blacklist-thread (atom nil))

(defn start []
  (init-db)
  (init-redis)
  (reset! cleanup-rate-thread (future (while true (Thread/sleep (:rate-limit-cleanup-interval config)) (cleanup-rate-limits))))
  (reset! cleanup-blacklist-thread (future (while true (Thread/sleep (:blacklist-cleanup-interval config)) (cleanup-blacklist))))
  (reset! server (jetty/run-jetty #'app {:port (:port config) :join? false})))

(defn stop []
  (future-cancel @cleanup-rate-thread)
  (future-cancel @cleanup-blacklist-thread)
  (when @server (.stop @server))
  (when @ds (hikari/close-datasource @ds)))

(defn -main [& _]
  (.addShutdownHook (Runtime/getRuntime) (Thread. stop))
  (start))
