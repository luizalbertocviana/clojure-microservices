(ns auth-server
  (:require [ring.adapter.jetty :as jetty]
            [reitit.ring :as ring]
            [reitit.coercion.spec]
            [reitit.ring.middleware.muuntaja :as muuntaja]
            [reitit.ring.middleware.exception :as exception]
            [reitit.ring.middleware.parameters :as parameters]
            [muuntaja.core :as m]
            [ring.middleware.cors :refer [wrap-cors]]
            [environ.core :refer [env]]
            [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs]
            [hikari-cp.core :as hikari]
            [taoensso.carmine :as car]
            [buddy.sign.jwt :as jwt]
            [buddy.hashers :as hashers]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [cheshire.core :as cheshire])
  (:import [com.zaxxer.hikari HikariDataSource]
           [ch.qos.logback.classic Level Logger]
           [org.slf4j LoggerFactory]
           [com.nulabinc.zxcvbn Zxcvbn])
  (:gen-class))

(defn set-log-level
  "Sets the log level for a given logger name (or root logger if nil)."
  [logger-name level]
  (let [level (case (str/upper-case (name level))
                "TRACE" Level/TRACE
                "DEBUG" Level/DEBUG
                "INFO" Level/INFO
                "WARN" Level/WARN
                "ERROR" Level/ERROR
                (throw (IllegalArgumentException. (str "Invalid log level: " level))))
        logger (if logger-name
                 (LoggerFactory/getLogger logger-name)
                 (LoggerFactory/getLogger Logger/ROOT_LOGGER_NAME))]
    (.setLevel logger level)
    (log/infof "Set log level for %s to %s" (or logger-name "root") (.toString level))))

(set-log-level nil :info)

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
      (log/error "Missing required environment variables" {:missing-keys (filter #(str/blank? (get cfg %)) [:jwt-secret :db-user :db-password :db-name :db-host])})
      (throw (ex-info "Missing required environment variables" {})))
    (log/info "Configuration loaded successfully" {:port (:port cfg) :db-host (:db-host cfg) :redis-host (:redis-host cfg)})
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
      (log/debug "Incremented Redis key" {:key key :count count :ttl-ms ttl-ms})
      count)
    (let [new-store (swap! in-memory-store (fn [store]
                                              (let [m (get store key)
                                                    curr (current-ms)
                                                    expired? (or (nil? m) (<= (:expire m) curr))
                                                    new-v (if expired? 1 (inc (:value m 0)))
                                                    new-exp (if expired? (+ curr ttl-ms) (:expire m))]
                                                (assoc store key {:value new-v :expire new-exp}))))]
      (log/debug "Incremented in-memory key" {:key key :count (get-in new-store [key :value]) :ttl-ms ttl-ms})
      (get-in new-store [key :value]))))

(defn my-get [key]
  (if (= @store-type :redis)
    (let [value (wcar* (car/get key))]
      (log/debug "Retrieved Redis key" {:key key :value value})
      value)
    (let [curr (current-ms)
          m (get @in-memory-store key)]
      (if (and m (> (:expire m) curr))
        (do
          (log/debug "Retrieved in-memory key" {:key key :value (:value m)})
          (:value m))
        (do
          (log/debug "Expired or missing in-memory key" {:key key})
          (swap! in-memory-store dissoc key)
          nil)))))

(defn my-set-ex [key val sec]
  (if (= @store-type :redis)
    (do
      (wcar* (car/set key val :ex sec))
      (log/debug "Set Redis key with expiry" {:key key :value val :expiry-sec sec}))
    (let [ms (* sec 1000)
          exp (+ (current-ms) ms)]
      (swap! in-memory-store assoc key {:value val :expire exp})
      (log/debug "Set in-memory key with expiry" {:key key :value val :expiry-ms ms}))))

(defn cleanup-rate-limits []
  (log/info "Starting rate limit cleanup")
  (if (= @store-type :redis)
    (doseq [k (wcar* (car/keys "rate:*"))]
      (when (<= (wcar* (car/pttl k)) 0)
        (wcar* (car/del k))
        (log/debug "Deleted expired Redis rate limit key" {:key k})))
    (swap! in-memory-store (fn [store]
                             (into {} (filter (fn [[k m]]
                                                (and (.startsWith k "rate:")
                                                     (> (:expire m) (current-ms))))
                                              store)))))
  (log/info "Completed rate limit cleanup"))

(defn cleanup-blacklist []
  (log/info "Starting blacklist cleanup")
  (if (= @store-type :redis)
    (doseq [k (wcar* (car/keys "blacklist:*"))]
      (when (<= (wcar* (car/ttl k)) 0)
        (wcar* (car/del k))
        (log/debug "Deleted expired Redis blacklist key" {:key k})))
    (swap! in-memory-store (fn [store]
                             (into {} (filter (fn [[k m]]
                                                (and (.startsWith k "blacklist:")
                                                     (> (:expire m) (current-ms))))
                                              store)))))
  (log/info "Completed blacklist cleanup"))

(defn create-datasource []
  (log/info "Creating database datasource" {:host (:db-host config) :port (:db-port config) :db-name (:db-name config)})
  (hikari/make-datasource {:adapter "postgresql"
                           :username (:db-user config)
                           :password (:db-password config)
                           :database-name (:db-name config)
                           :server-name (:db-host config)
                           :port-number (:db-port config)
                           :maximum-pool-size (:db-pool-size config)}))

(defn init-db []
  (log/info "Initializing database connection")
  (loop [attempt 1]
    (let [result (try
                   (reset! ds (create-datasource))
                   (jdbc/execute! @ds ["SELECT 1"])
                   (log/info "Database connection test successful")
                   (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP, token_version BIGINT DEFAULT 0);"])
                   (log/debug "Created users table if not exists")
                   (jdbc/execute! @ds ["CREATE UNIQUE INDEX IF NOT EXISTS users_lower_idx ON users (LOWER(username));"])
                   (log/debug "Created users_lower_idx index")
                   (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);"])
                   (log/debug "Created users_email_idx index")
                   (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS csrf_tokens (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), action VARCHAR(50) NOT NULL, expires_at TIMESTAMP NOT NULL);"])
                   (log/debug "Created csrf_tokens table")
                   (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS csrf_tokens_expires_idx ON csrf_tokens (expires_at);"])
                   (log/debug "Created csrf_tokens_expires_idx index")
                   (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS password_resets (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), expires_at TIMESTAMP NOT NULL);"])
                   (log/debug "Created password_resets table")
                   (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS password_resets_expires_idx ON password_resets (expires_at);"])
                   (log/debug "Created password_resets_expires_idx index")
                   (jdbc/execute! @ds ["CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, action VARCHAR(50) NOT NULL, username VARCHAR(255), ip VARCHAR(45), timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, details JSONB);"])
                   (log/debug "Created audit_log table")
                   (jdbc/execute! @ds ["CREATE INDEX IF NOT EXISTS audit_log_details_idx ON audit_log USING GIN (details);"])
                   (log/debug "Created audit_log_details_idx index")
                   (log/info "Database schema initialized successfully")
                   :success
                   (catch Exception e
                     (log/error "Database initialization failed" {:attempt attempt :error (.getMessage e)})
                     (if (<= attempt (:db-retries config))
                       :retry
                       (throw e))))]
      (if (= result :retry)
        (do
          (log/warn "Retrying database initialization" {:attempt (inc attempt)})
          (Thread/sleep 5000)
          (recur (inc attempt)))
        result))))

(defn init-redis []
  (log/info "Initializing Redis connection" {:host (:redis-host config) :port (:redis-port config)})
  (loop [attempt 1]
    (let [result (try
                   (wcar* (car/ping))
                   (log/info "Redis connection test successful")
                   :success
                   (catch Exception e
                     (log/error "Redis connection failed" {:attempt attempt :error (.getMessage e)})
                     ::error))]
      (if (and (= result ::error) (< attempt (:redis-retries config)))
        (do
          (log/warn "Retrying Redis connection" {:attempt (inc attempt)})
          (Thread/sleep 5000)
          (recur (inc attempt)))
        (when (= result ::error)
          (log/warn "Redis unavailable, using in-memory fallback for rate limiting and blacklisting")
          (reset! store-type :memory))))))

;; Utilities
(defn sanitize [s]
  (let [sanitized (str/escape s {\< "&lt;" \> "&gt;" \& "&amp;" \" "&quot;" \' "&#39;"})]
    (log/debug "Sanitized input" {:original s :sanitized sanitized})
    sanitized))

(defn valid-username? [u]
  (let [valid (and u (re-matches #"^[a-zA-Z0-9_-]{3,30}$" u))]
    (log/debug "Username validation" {:username u :valid valid})
    valid))

(defn valid-email? [e]
  (let [valid (and e (re-matches #"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" e))]
    (log/debug "Email validation" {:email e :valid valid})
    valid))

(defn valid-password? [p]
  (let [z (Zxcvbn.)
        strength (.measure z p)
        score (.getScore strength)
        valid (and p (>= (count p) 8)
                   (re-find #"[A-Z]" p)
                   (re-find #"\d" p)
                   (re-find #"[!@#$%^&*()_+-=]" p)
                   (not (contains? (:common-passwords config) (str/lower-case p)))
                   (>= score 2))]
    (log/debug "Password validation" {:score score :valid valid})
    valid))

(defn sign-token [claims expiry]
  (let [token (jwt/sign claims (:jwt-secret config) {:alg :hs512 :exp (+ (quot (System/currentTimeMillis) 1000) expiry)})]
    (log/debug "Signed JWT token" {:claims claims :expiry expiry})
    token))

(defn unsign-token [token]
  (try
    (let [claims (jwt/unsign token (:jwt-secret config) {:alg :hs512})]
      (log/debug "Unsigned JWT token" {:claims claims})
      claims)
    (catch Exception e
      (log/warn "Failed to unsign JWT token" {:error (.getMessage e)})
      nil)))

(defn generate-csrf [username action]
  (let [token (str (java.util.UUID/randomUUID))
        expires (java.sql.Timestamp. (+ (System/currentTimeMillis) (* (:csrf-token-expiry config) 1000)))]
    (jdbc/execute! @ds ["INSERT INTO csrf_tokens (token, username, action, expires_at) VALUES (?, ?, ?, ?)" token username action expires])
    (log/info "Generated CSRF token" {:username username :action action})
    token))

(defn validate-csrf [token username action]
  (let [row (jdbc/execute-one! @ds ["SELECT * FROM csrf_tokens WHERE token = ? AND (username = ? OR username IS NULL) AND action = ? AND expires_at > NOW()" token username action])]
    (if row
      (do
        (jdbc/execute! @ds ["DELETE FROM csrf_tokens WHERE token = ?" token])
        (log/info "Validated CSRF token" {:username username :action action})
        true)
      (do
        (log/warn "Invalid or expired CSRF token" {:username username :action action :token token})
        false))))

(defn audit [action username ip details]
  (jdbc/execute! @ds ["INSERT INTO audit_log (action, username, ip, details) VALUES (?, ?, ?, ?::jsonb)" action username ip (cheshire/generate-string details)])
  (log/info "Logged audit event" {:action action :username username :ip ip :details details}))

(defn get-db-token-version [username]
  (let [version (:token_version (jdbc/execute-one! @ds ["SELECT token_version FROM users WHERE username = ?" username] {:builder-fn rs/as-unqualified-maps}))]
    (log/debug "Retrieved token version" {:username username :version version})
    version))

(defn user-exists? [username email]
  (let [exists (boolean (jdbc/execute-one! @ds ["SELECT 1 FROM users WHERE LOWER(username) = LOWER(?) OR email = ?" username email]))]
    (log/debug "Checked user existence" {:username username :email email :exists exists})
    exists))

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
        (do
          (log/warn "Rate limit exceeded" {:ip ip :path path :count count})
          {:status 429 :body {:error "Rate limit exceeded"}})
        (do
          (log/debug "Rate limit check passed" {:ip ip :path path :count count})
          (handler req))))))

(defn secure-headers-middleware [handler]
  (fn [req]
    (log/debug "Applying secure headers" {:path (:uri req)})
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
      (log/debug "Checking authorization" {:has-auth (boolean auth)})
      (if-not token
        (do
          (log/warn "Missing authorization token" {:path (:uri req) :ip (:remote-addr req)})
          {:status 401 :body {:error "Missing token"}})
        (if (my-get (str "blacklist:" token))
          (do
            (log/warn "Blacklisted token detected" {:path (:uri req) :ip (:remote-addr req)})
            {:status 401 :body {:error "Blacklisted token"}})
          (let [claims (unsign-token token)]
            (if-not claims
              (do
                (log/warn "Invalid token" {:path (:uri req) :ip (:remote-addr req)})
                {:status 401 :body {:error "Invalid token"}})
              (let [{:keys [username token_version]} claims
                    db-v (get-db-token-version username)]
                (if (and db-v (= token_version db-v))
                  (do
                    (log/info "Authentication successful" {:username username :path (:uri req)})
                    (handler (assoc req :identity {:username username} :claims claims)))
                  (do
                    (log/warn "Invalid token version" {:username username :path (:uri req) :token-version token_version :db-version db-v})
                    {:status 401 :body {:error "Invalid token version"}}))))))))))

;; Handlers
(defn csrf-handler [req]
  (let [action (get-in req [:path-params :action])
        username (get-in req [:identity :username])]
    (log/info "Generating CSRF token for action" {:action action :username username})
    {:status 200 :body {:csrfToken (generate-csrf username action)}}))

(defn register-handler [req]
  (let [body (:body-params req)
        username (sanitize (get body :username))
        password (get body :password)
        email (sanitize (get body :email))
        csrf-token (get body :csrfToken)
        ip (:remote-addr req)]
    (log/info "Processing registration request" {:username username :email email :ip ip})
    (cond
      (not (and (valid-username? username) (valid-password? password) (valid-email? email)))
      (do
        (log/warn "Invalid registration input" {:username username :email email :ip ip})
        {:status 400 :body {:error "Invalid input"}})

      (not (validate-csrf csrf-token nil "register"))
      (do
        (log/warn "Invalid CSRF token for registration" {:username username :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})

      (user-exists? username email)
      (do
        (log/warn "Username or email already exists" {:username username :email email :ip ip})
        {:status 409 :body {:error "Username or email already exists"}})

      :else
      (let [hashed (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
        (jdbc/with-transaction [tx @ds]
          (jdbc/execute! tx ["INSERT INTO users (username, password, email) VALUES (?, ?, ?)" username hashed email])
          (log/info "User registered successfully" {:username username :email email :ip ip})
          (audit "register" username ip {:email email}))
        {:status 201 :body {:message "User registered successfully"}}))))

(defn login-handler [req]
  (let [body (:body-params req)
        username (get body :username)
        password (get body :password)
        csrf-token (get body :csrfToken)
        ip (:remote-addr req)
        bucket (quot (System/currentTimeMillis) (:rate-limit-window config))
        rate-key (str "rate:login:" (str/lower-case username) ":" bucket)
        ttl (- (:rate-limit-window config) (mod (System/currentTimeMillis) (:rate-limit-window config)))
        count (my-incr rate-key ttl)]
    (log/info "Processing login request" {:username username :ip ip})
    (cond
      (> count (:rate-limit-login-attempts config))
      (do
        (log/warn "Login rate limit exceeded" {:username username :ip ip :count count})
        {:status 429 :body {:error "Rate limit exceeded"}})

      (not (validate-csrf csrf-token nil "login"))
      (do
        (log/warn "Invalid CSRF token for login" {:username username :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})

      :else
      (let [user (jdbc/execute-one! @ds ["SELECT * FROM users WHERE LOWER(username) = LOWER(?)" username] {:builder-fn rs/as-unqualified-maps})]
        (if-not user
          (do
            (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})
            (Thread/sleep (rand-int 500))
            (log/warn "Login failed: user not found" {:username username :ip ip})
            (audit "login_failed" username ip {})
            {:status 401 :body {:error "Invalid credentials"}})
          (if-not (hashers/check password (:password user))
            (do
              (Thread/sleep (rand-int 500))
              (log/warn "Login failed: invalid password" {:username username :ip ip})
              (audit "login_failed" username ip {})
              {:status 401 :body {:error "Invalid credentials"}})
            (let [db-v (:token_version user)
                  access (sign-token {:username username :token_version db-v} (:token-expiry config))
                  refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
                  new-csrf (generate-csrf username "post-login")]
              (jdbc/execute! @ds ["UPDATE users SET last_login = NOW() WHERE username = ?" username])
              (log/info "Login successful" {:username username :ip ip})
              (audit "login_success" username ip {})
              {:status 200 :body {:token access :refreshToken refresh :csrfToken new-csrf}})))))))

(defn refresh-handler [req]
  (let [body (:body-params req)
        refresh-token (get body :refreshToken)
        csrf-token (get body :csrfToken)
        ip (:remote-addr req)]
    (log/info "Processing token refresh request" {:ip ip})
    (cond
      (not refresh-token)
      (do
        (log/warn "Missing refresh token" {:ip ip})
        {:status 400 :body {:error "Invalid input"}})

      :else
      (let [claims (unsign-token refresh-token)]
        (cond
          (not claims)
          (do
            (log/warn "Invalid or expired refresh token" {:ip ip})
            {:status 401 :body {:error "Invalid/expired refresh token"}})

          (my-get (str "blacklist:" refresh-token))
          (do
            (log/warn "Blacklisted refresh token" {:ip ip})
            {:status 401 :body {:error "Blacklisted token"}})

          :else
          (let [username (:username claims)
                db-v (get-db-token-version username)]
            (cond
              (not (= (:token_version claims) db-v))
              (do
                (log/warn "Invalid token version for refresh" {:username username :ip ip})
                {:status 401 :body {:error "Invalid token version"}})

              (not (validate-csrf csrf-token username "refresh"))
              (do
                (log/warn "Invalid CSRF token for refresh" {:username username :ip ip})
                {:status 401 :body {:error "Invalid/missing CSRF token"}})

              :else
              (let [new-access (sign-token {:username username :token_version db-v} (:token-expiry config))
                    new-refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
                    ttl (- (:exp claims) (quot (System/currentTimeMillis) 1000))]
                (my-set-ex (str "blacklist:" refresh-token) "1" ttl)
                (log/info "Token refreshed successfully" {:username username :ip ip})
                {:status 200 :body {:token new-access :refreshToken new-refresh}}))))))))

(defn logout-handler [req]
  (let [csrf (get-in req [:headers "x-csrf-token"])
        username (get-in req [:identity :username])
        claims (:claims req)
        token (subs (get-in req [:headers "authorization"]) 7)
        ip (:remote-addr req)]
    (log/info "Processing logout request" {:username username :ip ip})
    (cond
      (not (validate-csrf csrf username "logout"))
      (do
        (log/warn "Invalid CSRF token for logout" {:username username :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})

      :else
      (do
        (jdbc/execute! @ds ["UPDATE users SET token_version = token_version + 1 WHERE username = ?" username])
        (let [ttl (- (:exp claims) (quot (System/currentTimeMillis) 1000))]
          (my-set-ex (str "blacklist:" token) "1" ttl))
        (log/info "Logout successful" {:username username :ip ip})
        (audit "logout" username ip {})
        {:status 200 :body {:message "Logged out successfully"}}))))

(defn forgot-handler [req]
  (let [body (:body req)
        email (sanitize (get body "email"))
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)]
    (log/info "Processing forgot password request" {:email email :ip ip})
    (cond
      (not (valid-email? email))
      (do
        (log/warn "Invalid email for password reset" {:email email :ip ip})
        {:status 400 :body {:error "Invalid input"}})

      (not (validate-csrf csrf-token nil "forgot-password"))
      (do
        (log/warn "Invalid CSRF token for password reset" {:email email :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})

      :else
      (let [user (jdbc/execute-one! @ds ["SELECT username FROM users WHERE email = ?" email])]
        (if user
          (let [token (str (java.util.UUID/randomUUID))
                expires (java.sql.Timestamp. (+ (System/currentTimeMillis) (* (:password-reset-expiry config) 1000)))]
            (jdbc/execute! @ds ["INSERT INTO password_resets (token, username, expires_at) VALUES (?, ?, ?)" token (:username user) expires])
            (log/info "Password reset token generated" {:username (:username user) :email email :ip ip})
            (audit "password_reset_requested" (:username user) ip {:email email})
            {:status 200 :body {:message "If the email exists, a reset link has been sent" :resetToken token}})
          (do
            (str (java.util.UUID/randomUUID))
            (log/info "Password reset requested for non-existent email" {:email email :ip ip})
            {:status 200 :body {:message "If the email exists, a reset link has been sent"}}))))))

(defn reset-handler [req]
  (let [body (:body req)
        token (get body "token")
        new-password (get body "newPassword")
        csrf-token (get body "csrfToken")
        ip (:remote-addr req)]
    (log/info "Processing password reset request" {:ip ip})
    (cond
      (not (and token (valid-password? new-password)))
      (do
        (log/warn "Invalid input for password reset" {:ip ip})
        {:status 400 :body {:error "Invalid input"}})

      :else
      (let [reset (jdbc/execute-one! @ds ["SELECT username FROM password_resets WHERE token = ? AND expires_at > NOW()" token])]
        (cond
          (not reset)
          (do
            (log/warn "Invalid or expired password reset token" {:ip ip})
            {:status 401 :body {:error "Invalid/expired reset token"}})

          (not (validate-csrf csrf-token (:username reset) "reset-password"))
          (do
            (log/warn "Invalid CSRF token for password reset" {:username (:username reset) :ip ip})
            {:status 401 :body {:error "Invalid/missing CSRF token"}})

          :else
          (let [hashed (hashers/derive new-password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
            (jdbc/with-transaction [tx @ds]
              (jdbc/execute! tx ["UPDATE users SET password = ?, token_version = token_version + 1 WHERE username = ?" hashed (:username reset)])
              (jdbc/execute! tx ["DELETE FROM password_resets WHERE token = ?" token])
              (log/info "Password reset successful" {:username (:username reset) :ip ip})
              (audit "password_reset" (:username reset) ip {}))
            {:status 200 :body {:message "Password reset successfully"}}))))))

(defn health-handler [_]
  (log/info "Processing health check request")
  (let [db-ok (try
                (jdbc/execute! @ds ["SELECT 1"])
                (log/debug "Database health check passed")
                true
                (catch Exception e
                  (log/error "Database health check failed" {:error (.getMessage e)})
                  false))
        redis-ok (try
                   (when (= @store-type :redis)
                     (wcar* (car/ping))
                     (log/debug "Redis health check passed")
                     true)
                   (catch Exception e
                     (log/warn "Redis health check failed" {:error (.getMessage e)})
                     false))
        jwt-ok (let [test-claims {:test 1}
                     test-token (sign-token test-claims 10)
                     unsign-claims (unsign-token test-token)]
                 (if (and test-token unsign-claims (= (:test unsign-claims) 1))
                   (do
                     (log/debug "JWT health check passed")
                     true)
                   (do
                     (log/error "JWT health check failed")
                     false)))
        rate-limit-size (if (= @store-type :redis)
                          (count (wcar* (car/keys "rate:*")))
                          (count (filter #(.startsWith ^String % "rate:") (keys @in-memory-store))))
        pool-stats (let [hikari-pool (.getHikariPoolMXBean ^HikariDataSource @ds)]
                     (.getTotalConnections hikari-pool))]
    (log/info "Health check completed" {:db-ok db-ok :redis-ok redis-ok :jwt-ok jwt-ok :rate-limit-size rate-limit-size :pool-stats pool-stats})
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
(def muuntaja (m/create m/default-options))

(def app
  (ring/ring-handler
   (ring/router
    [["/csrf/{action}" {:get csrf-handler}]
     ["/register" {:post register-handler}]
     ["/login" {:post login-handler}]
     ["/refresh" {:post refresh-handler}]
     ["/validate" {:get {:middleware [auth-middleware]
                         :handler (fn [req]
                                    (log/info "Token validation request" {:username (get-in req [:identity :username])})
                                    {:status 200 :body {:username (get-in req [:identity :username])}})}}]
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
                         (fn [handler]
                           (wrap-cors handler
                                      :access-control-allow-origin (:allowed-origins config)
                                      :access-control-allow-methods [:get :post :options]
                                      :access-control-allow-headers ["Content-Type" "Authorization" "X-CSRF-Token"]))]}})
   (ring/create-default-handler
     {:not-found (fn [_]
                   (log/warn "Route not found")
                   {:status 404 :headers {"Content-Type" "application/json"} :body (cheshire/encode {:error "Not found"})})})))

;; Server
(def server (atom nil))
(def cleanup-rate-thread (atom nil))
(def cleanup-blacklist-thread (atom nil))

(defn start []
  (log/info "Starting auth server")
  (init-db)
  (init-redis)
  (reset! cleanup-rate-thread (future (while true (Thread/sleep (:rate-limit-cleanup-interval config)) (cleanup-rate-limits))))
  (log/info "Started rate limit cleanup thread")
  (reset! cleanup-blacklist-thread (future (while true (Thread/sleep (:blacklist-cleanup-interval config)) (cleanup-blacklist))))
  (log/info "Started blacklist cleanup thread")
  (reset! server (jetty/run-jetty #'app {:port (:port config) :join? false}))
  (log/info "Auth server started" {:port (:port config)}))

(defn stop []
  (log/info "Stopping auth server")
  (future-cancel @cleanup-rate-thread)
  (log/info "Stopped rate limit cleanup thread")
  (future-cancel @cleanup-blacklist-thread)
  (log/info "Stopped blacklist cleanup thread")
  (when @server
    (.stop @server)
    (log/info "Jetty server stopped"))
  (when @ds
    (hikari/close-datasource @ds)
    (log/info "Database datasource closed")))

(defn -main [& _]
  (log/info "Main function invoked")
  (.addShutdownHook (Runtime/getRuntime) (Thread. stop))
  (start))

(comment
  (set-log-level nil :info)
  (set-log-level "auth-server" :debug)
  (stop)
  (start))
