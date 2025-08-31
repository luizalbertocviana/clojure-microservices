(ns auth-server
  (:require [ring.adapter.jetty :as jetty]
            [reitit.ring :as ring]
            [reitit.coercion.spec]
            [reitit.ring.middleware.muuntaja :as muuntaja]
            [reitit.ring.middleware.exception :as exception]
            [reitit.ring.middleware.parameters :as parameters]
            [muuntaja.core :as m]
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

;; Constants
(def ^:private jwt-algorithm :hs512)
(def ^:private login-delay-ms 500)
(def ^:private sql-queries
  {:create-users-table "CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP, token_version BIGINT DEFAULT 0)"
   :create-users-lower-idx "CREATE UNIQUE INDEX IF NOT EXISTS users_lower_idx ON users (LOWER(username))"
   :create-users-email-idx "CREATE INDEX IF NOT EXISTS users_email_idx ON users (email)"
   :create-csrf-table "CREATE TABLE IF NOT EXISTS csrf_tokens (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), action VARCHAR(50) NOT NULL, expires_at TIMESTAMP NOT NULL)"
   :create-csrf-expires-idx "CREATE INDEX IF NOT EXISTS csrf_tokens_expires_idx ON csrf_tokens (expires_at)"
   :create-password-resets-table "CREATE TABLE IF NOT EXISTS password_resets (token VARCHAR(64) PRIMARY KEY, username VARCHAR(255) REFERENCES users(username), expires_at TIMESTAMP NOT NULL)"
   :create-password-resets-expires-idx "CREATE INDEX IF NOT EXISTS password_resets_expires_idx ON password_resets (expires_at)"
   :create-audit-log-table "CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, action VARCHAR(50) NOT NULL, username VARCHAR(255), ip VARCHAR(45), timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, details JSONB)"
   :create-audit-log-details-idx "CREATE INDEX IF NOT EXISTS audit_log_details_idx ON audit_log USING GIN (details)"
   :find-user-by-username "SELECT * FROM users WHERE LOWER(username) = LOWER(?)"
   :find-user-by-email "SELECT username FROM users WHERE email = ?"
   :insert-user "INSERT INTO users (username, password, email) VALUES (?, ?, ?)"
   :update-user-password "UPDATE users SET password = ?, token_version = token_version + 1 WHERE username = ?"
   :update-user-last-login "UPDATE users SET last_login = NOW() WHERE username = ?"
   :update-user-token-version "UPDATE users SET token_version = token_version + 1 WHERE username = ?"
   :insert-csrf-token "INSERT INTO csrf_tokens (token, username, action, expires_at) VALUES (?, ?, ?, ?)"
   :find-csrf-token "SELECT * FROM csrf_tokens WHERE token = ? AND (username = ? OR username IS NULL) AND action = ? AND expires_at > NOW()"
   :delete-csrf-token "DELETE FROM csrf_tokens WHERE token = ?"
   :insert-password-reset "INSERT INTO password_resets (token, username, expires_at) VALUES (?, ?, ?)"
   :find-password-reset "SELECT username FROM password_resets WHERE token = ? AND expires_at > NOW()"
   :delete-password-reset "DELETE FROM password_resets WHERE token = ?"
   :insert-audit-log "INSERT INTO audit_log (action, username, ip, details) VALUES (?, ?, ?, ?::jsonb)"
   :test-connection "SELECT 1"})

;; Configuration
(def ^:private config
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
(def ^:private ds (atom nil))
(def ^:private redis-conn {:pool {} :spec {:host (:redis-host config) :port (:redis-port config)}})
(defmacro ^:private wcar* [& body] `(car/wcar redis-conn ~@body))

(defn- set-log-level
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

(defn- current-ms
  "Returns the current time in milliseconds."
  [] (System/currentTimeMillis))

(defn- my-incr
  "Increments a Redis key and sets its expiry."
  [key ttl-ms]
  (let [count (wcar* (car/incr key))]
    (wcar* (car/pexpire key ttl-ms))
    (log/debug "Incremented Redis key" {:key key :count count :ttl-ms ttl-ms})
    count))

(defn- my-get
  "Retrieves a value from Redis by key."
  [key]
  (let [value (wcar* (car/get key))]
    (log/debug "Retrieved Redis key" {:key key :value value})
    value))

(defn- my-set-ex
  "Sets a Redis key with a value and expiry."
  [key val sec]
  (wcar* (car/set key val :ex sec))
  (log/debug "Set Redis key with expiry" {:key key :value val :expiry-sec sec}))

(defn- cleanup-rate-limits
  "Cleans up expired rate limit keys in Redis."
  []
  (log/info "Starting rate limit cleanup")
  (doseq [k (wcar* (car/keys "rate:*"))]
    (when (<= (wcar* (car/pttl k)) 0)
      (wcar* (car/del k))
      (log/debug "Deleted expired Redis rate limit key" {:key k})))
  (log/info "Completed rate limit cleanup"))

(defn- cleanup-blacklist
  "Cleans up expired blacklist keys in Redis."
  []
  (log/info "Starting blacklist cleanup")
  (doseq [k (wcar* (car/keys "blacklist:*"))]
    (when (<= (wcar* (car/ttl k)) 0)
      (wcar* (car/del k))
      (log/debug "Deleted expired Redis blacklist key" {:key k})))
  (log/info "Completed blacklist cleanup"))

(defn- create-datasource
  "Creates a HikariCP datasource for PostgreSQL."
  []
  (log/info "Creating database datasource" {:host (:db-host config) :port (:db-port config) :db-name (:db-name config)})
  (hikari/make-datasource {:adapter "postgresql"
                           :username (:db-user config)
                           :password (:db-password config)
                           :database-name (:db-name config)
                           :server-name (:db-host config)
                           :port-number (:db-port config)
                           :maximum-pool-size (:db-pool-size config)}))

(defn- init-tables
  "Initializes database schema (tables and indexes)."
  [ds]
  (jdbc/execute! ds [(:create-users-table sql-queries)])
  (log/debug "Created users table if not exists")
  (jdbc/execute! ds [(:create-users-lower-idx sql-queries)])
  (log/debug "Created users_lower_idx index")
  (jdbc/execute! ds [(:create-users-email-idx sql-queries)])
  (log/debug "Created users_email_idx index")
  (jdbc/execute! ds [(:create-csrf-table sql-queries)])
  (log/debug "Created csrf_tokens table")
  (jdbc/execute! ds [(:create-csrf-expires-idx sql-queries)])
  (log/debug "Created csrf_tokens_expires_idx index")
  (jdbc/execute! ds [(:create-password-resets-table sql-queries)])
  (log/debug "Created password_resets table")
  (jdbc/execute! ds [(:create-password-resets-expires-idx sql-queries)])
  (log/debug "Created password_resets_expires_idx index")
  (jdbc/execute! ds [(:create-audit-log-table sql-queries)])
  (log/debug "Created audit_log table")
  (jdbc/execute! ds [(:create-audit-log-details-idx sql-queries)])
  (log/debug "Created audit_log_details_idx index"))

(defn- init-db
  "Initializes the database connection with retries."
  []
  (log/info "Initializing database connection")
  (loop [attempt 1]
    (let [result (try
                   (let [new-ds (create-datasource)]
                     (reset! ds new-ds)
                     (jdbc/execute! @ds [(:test-connection sql-queries)])
                     (log/info "Database connection test successful")
                     (init-tables @ds)
                     (log/info "Database schema initialized successfully")
                     :success)
                   (catch java.sql.SQLException e
                     (log/error "Database initialization failed" {:attempt attempt :error (.getMessage e)})
                     (if (<= attempt (:db-retries config))
                       :retry
                       (throw e))))]
      (if (= result :retry)
        (do
          (log/warn "Retrying database initialization" {:attempt (inc attempt)})
          (Thread/sleep login-delay-ms)
          (recur (inc attempt)))
        result))))

(defn- init-redis
  "Initializes the Redis connection with retries."
  []
  (log/info "Initializing Redis connection" {:host (:redis-host config) :port (:redis-port config)})
  (loop [attempt 1]
    (let [result (try
                   (wcar* (car/ping))
                   (log/info "Redis connection test successful")
                   :success
                   (catch Exception e
                     (log/error "Redis connection failed" {:attempt attempt :error (.getMessage e)})
                     (if (< attempt (:redis-retries config))
                       :retry
                       (throw (ex-info "Redis initialization failed after retries" {:error (.getMessage e)})))))]
      (if (= result :retry)
        (do
          (log/warn "Retrying Redis connection" {:attempt (inc attempt)})
          (Thread/sleep login-delay-ms)
          (recur (inc attempt)))
        result))))

;; Crypto Utilities
(defn- sign
  "Signs a JWT with the given claims and expiry."
  [claims secret expiry]
  (jwt/sign claims secret {:alg jwt-algorithm :exp (+ (quot (current-ms) 1000) expiry)}))

(defn- unsign
  "Unsigs a JWT and returns its claims, or nil if invalid."
  [token secret]
  (try
    (jwt/unsign token secret {:alg jwt-algorithm})
    (catch Exception _ nil)))

;; Database Utilities
(defn- find-user-by-username
  "Finds a user by username (case-insensitive)."
  [ds username]
  (jdbc/execute-one! ds [(:find-user-by-username sql-queries) username] {:builder-fn rs/as-unqualified-maps}))

(defn- find-user-by-email
  "Finds a user by email."
  [ds email]
  (jdbc/execute-one! ds [(:find-user-by-email sql-queries) email] {:builder-fn rs/as-unqualified-maps}))

(defn- create-user
  "Inserts a new user into the database."
  [ds username password email]
  (jdbc/execute! ds [(:insert-user sql-queries) username password email]))

(defn- update-user-password
  "Updates a user's password and increments token version."
  [ds username password]
  (jdbc/execute! ds [(:update-user-password sql-queries) password username]))

(defn- update-user-last-login
  "Updates a user's last login timestamp."
  [ds username]
  (jdbc/execute! ds [(:update-user-last-login sql-queries) username]))

(defn- update-user-token-version
  "Increments a user's token version."
  [ds username]
  (jdbc/execute! ds [(:update-user-token-version sql-queries) username]))

(defn- insert-csrf-token
  "Inserts a CSRF token into the database."
  [ds token username action expires]
  (jdbc/execute! ds [(:insert-csrf-token sql-queries) token username action expires]))

(defn- find-csrf-token
  "Finds a CSRF token by token, username, and action."
  [ds token username action]
  (jdbc/execute-one! ds [(:find-csrf-token sql-queries) token username action]))

(defn- delete-csrf-token
  "Deletes a CSRF token from the database."
  [ds token]
  (jdbc/execute! ds [(:delete-csrf-token sql-queries) token]))

(defn- insert-password-reset
  "Inserts a password reset token into the database."
  [ds token username expires]
  (jdbc/execute! ds [(:insert-password-reset sql-queries) token username expires]))

(defn- find-password-reset
  "Finds a password reset token."
  [ds token]
  (jdbc/execute-one! ds [(:find-password-reset sql-queries) token] {:builder-fn rs/as-unqualified-maps}))

(defn- delete-password-reset
  "Deletes a password reset token."
  [ds token]
  (jdbc/execute! ds [(:delete-password-reset sql-queries) token]))

(defn- insert-audit-log
  "Inserts an audit log entry."
  [ds action username ip details]
  (jdbc/execute! ds [(:insert-audit-log sql-queries) action username ip (cheshire/generate-string details)]))

;; General Utilities
(defn- sanitize
  "Sanitizes input to prevent XSS."
  [s]
  (let [sanitized (str/escape s {\< "&lt;" \> "&gt;" \& "&amp;" \" "&quot;" \' "&#39;"})]
    (log/debug "Sanitized input" {:original s :sanitized sanitized})
    sanitized))

(defn- valid-username?
  "Validates a username: 3-30 characters, alphanumeric, underscore, or hyphen."
  [u]
  (let [valid (and u (re-matches #"^[a-zA-Z0-9_-]{3,30}$" u))]
    (log/debug "Username validation" {:username u :valid valid})
    valid))

(defn- valid-email?
  "Validates an email address format."
  [e]
  (let [valid (and e (re-matches #"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" e))]
    (log/debug "Email validation" {:email e :valid valid})
    valid))

(defn- valid-password?
  "Validates a password: at least 8 characters, one uppercase, one digit, one special character, not common, and strong enough."
  [p]
  (let [z (Zxcvbn.)
        strength (.measure z p)
        score (.getScore strength)
        valid (and p (>= (count p) 8)
                   (re-find #"[A-Z]" p)
                   (re-find #"\d" p)
                   (re-find #"[!@#$%^&*()_+\-=]" p)
                   (not (contains? (:common-passwords config) (str/lower-case p)))
                   (>= score 2))]
    (log/debug "Password validation" {:score score :valid valid})
    valid))

(defn- sign-token
  "Signs a JWT token with user claims."
  [claims expiry]
  (let [token (sign claims (:jwt-secret config) expiry)]
    (log/debug "Signed JWT token" {:claims claims :expiry expiry})
    token))

(defn- unsign-token
  "Unsigs a JWT token and returns its claims."
  [token]
  (let [claims (unsign token (:jwt-secret config))]
    (log/debug "Unsigned JWT token" {:claims claims})
    claims))

(defn- generate-csrf
  "Generates a CSRF token for a user and action."
  [ds username action]
  (let [token (str (java.util.UUID/randomUUID))
        expires (java.sql.Timestamp. (+ (current-ms) (* (:csrf-token-expiry config) 1000)))]
    (insert-csrf-token ds token username action expires)
    (log/info "Generated CSRF token" {:username username :action action})
    token))

(defn- validate-csrf
  "Validates a CSRF token for a user and action."
  [ds token username action]
  (let [row (find-csrf-token ds token username action)]
    (if row
      (do
        (delete-csrf-token ds token)
        (log/info "Validated CSRF token" {:username username :action action})
        true)
      (do
        (log/warn "Invalid or expired CSRF token" {:username username :action action :token token})
        false))))

(defn- audit
  "Logs an audit event."
  [ds action username ip details]
  (insert-audit-log ds action username ip details)
  (log/info "Logged audit event" {:action action :username username :ip ip :details details}))

(defn- get-db-token-version
  "Retrieves the token version for a user."
  [ds username]
  (let [version (:token_version (find-user-by-username ds username))]
    (log/debug "Retrieved token version" {:username username :version version})
    version))

(defn- user-exists?
  "Checks if a user exists by username or email."
  [ds username email]
  (let [exists (boolean (or (find-user-by-username ds username)
                            (find-user-by-email ds email)))]
    (log/debug "Checked user existence" {:username username :email email :exists exists})
    exists))

;; Middleware
(defn- check-rate-limit
  "Checks if the request exceeds the rate limit."
  [ip path]
  (let [bucket (quot (current-ms) (:rate-limit-window config))
        key (str "rate:ip:" ip ":" path ":" bucket)
        ttl (- (:rate-limit-window config) (mod (current-ms) (:rate-limit-window config)))
        count (my-incr key ttl)]
    (if (> count (:rate-limit-requests config))
      (do
        (log/warn "Rate limit exceeded" {:ip ip :path path :count count})
        {:status 429 :body {:error "Rate limit exceeded"}})
      (do
        (log/debug "Rate limit check passed" {:ip ip :path path :count count})
        nil))))

(defn- rate-limit-middleware
  "Middleware to enforce rate limiting."
  [handler]
  (fn [req]
    (let [ip (:remote-addr req)
          path (:uri req)]
      (or (check-rate-limit ip path)
          (handler req)))))

(defn- secure-headers-middleware
  "Middleware to add secure HTTP headers."
  [handler]
  (fn [req]
    (log/debug "Applying secure headers" {:path (:uri req)})
    (let [resp (handler req)]
      (-> resp
          (assoc-in [:headers "Strict-Transport-Security"] "max-age=31536000; includeSubDomains")
          (assoc-in [:headers "Content-Security-Policy"] "default-src 'self'; script-src 'self'; object-src 'none'")
          (assoc-in [:headers "X-Content-Type-Options"] "nosniff")
          (assoc-in [:headers "X-Frame-Options"] "DENY")))))

(defn- cors-middleware
  "Middleware to handle CORS requests."
  [handler allowed-origins]
  (fn [req]
    (let [headers (into {} (map (fn [[k v]] [(clojure.string/lower-case k) v]) (:headers req)))
          origin (get headers "origin")
          acrm (get headers "access-control-request-method")
          acrih (get headers "access-control-request-headers")
          allowed-methods #{"GET" "POST" "OPTIONS"}
          allowed-headers #{"content-type" "authorization" "x-csrf-token" "x-requested-with"}]
      (if (= (:request-method req) :options)
        (if (and origin
                 (contains? allowed-origins origin)
                 (or (nil? acrm) (contains? allowed-methods (clojure.string/upper-case acrm)))
                 (or (nil? acrih)
                     (every? #(contains? allowed-headers (clojure.string/lower-case (clojure.string/trim %)))
                             (clojure.string/split acrih #","))))
          {:status 200
           :headers {"Access-Control-Allow-Origin" origin
                     "Access-Control-Allow-Methods" "GET,POST,OPTIONS"
                     "Access-Control-Allow-Headers" "Content-Type,Authorization,X-CSRF-Token,X-Requested-With"
                     "Access-Control-Max-Age" "86400"
                     "Vary" "Origin"}}
          {:status 403 :body {:error "CORS preflight request denied"}})
        (let [resp (handler req)]
          (if (and origin (contains? allowed-origins origin))
            (assoc-in resp [:headers]
                      (merge (:headers resp)
                             {"Access-Control-Allow-Origin" origin
                              "Vary" "Origin"}))
            resp))))))

(defn- logger-middleware
  "Middleware to log request details."
  [handler]
  (fn [req]
    (let [start (current-ms)
          resp (handler req)
          duration (- (current-ms) start)
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

(defn- extract-token
  "Extracts the JWT token from the Authorization header."
  [req]
  (let [auth (get-in req [:headers "authorization"])]
    (when (and auth (str/starts-with? (str/lower-case auth) "bearer "))
      (subs auth 7))))

(defn- check-blacklist
  "Checks if a token is blacklisted."
  [token]
  (when (my-get (str "blacklist:" token))
    {:status 401 :body {:error "Blacklisted token"}}))

(defn- validate-token
  "Validates a JWT token and checks token version."
  [ds token path ip]
  (if-not token
    (do
      (log/warn "Missing authorization token" {:path path :ip ip})
      {:status 401 :body {:error "Missing token"}})
    (if-let [claims (unsign-token token)]
      (let [{:keys [username token_version]} claims
            db-v (get-db-token-version ds username)]
        (if (and db-v (= token_version db-v))
          {:username username :claims claims}
          (do
            (log/warn "Invalid token version" {:username username :path path :token-version token_version :db-version db-v})
            {:status 401 :body {:error "Invalid token version"}})))
      (do
        (log/warn "Invalid token" {:path path :ip ip})
        {:status 401 :body {:error "Invalid token"}}))))

(defn- auth-middleware
  "Middleware to authenticate requests using JWT."
  [handler]
  (fn [req]
    (let [token (extract-token req)
          path (:uri req)
          ip (:remote-addr req)]
      (or (check-blacklist token)
          (let [result (validate-token @ds token path ip)]
            (if (:status result)
              result
              (handler (assoc req :identity {:username (:username result)} :claims (:claims result)))))))))

;; Handlers
(defn- check-login-rate-limit
  "Checks if login attempts exceed the rate limit."
  [username ip]
  (let [bucket (quot (current-ms) (:rate-limit-window config))
        rate-key (str "rate:login:" (str/lower-case username) ":" bucket)
        ttl (- (:rate-limit-window config) (mod (current-ms) (:rate-limit-window config)))
        count (my-incr rate-key ttl)]
    (if (> count (:rate-limit-login-attempts config))
      (do
        (log/warn "Login rate limit exceeded" {:username username :ip ip :count count})
        {:status 429 :body {:error "Login Rate limit exceeded"}})
      nil)))

(defn- validate-login-input
  "Validates login request input."
  [username password csrf-token ip]
  (cond
    (not (and username password csrf-token))
    (do
      (log/warn "Missing login input" {:username username :ip ip})
      {:status 400 :body {:error "Missing username, password, or CSRF token"}})
    (not (validate-csrf @ds csrf-token nil "login"))
    (do
      (log/warn "Invalid CSRF token for login" {:username username :ip ip})
      {:status 401 :body {:error "Invalid/missing CSRF token"}})))

(defn- authenticate-user
  "Authenticates a user and generates tokens."
  [ds username password ip]
  (let [user (find-user-by-username ds username)]
    (if-not user
      (do
        (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})
        (Thread/sleep (rand-int login-delay-ms))
        (log/warn "Login failed: user not found" {:username username :ip ip})
        (audit ds "login_failed" username ip {})
        {:status 401 :body {:error "Invalid username or password"}})
      (if-not (hashers/check password (:password user))
        (do
          (Thread/sleep (rand-int login-delay-ms))
          (log/warn "Login failed: invalid password" {:username username :ip ip})
          (audit ds "login_failed" username ip {})
          {:status 401 :body {:error "Invalid username or password"}})
        (let [db-v (:token_version user)
              access (sign-token {:username username :token_version db-v} (:token-expiry config))
              refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
              new-csrf (generate-csrf ds username "post-login")]
          (update-user-last-login ds username)
          (log/info "Login successful" {:username username :ip ip})
          (audit ds "login_success" username ip {})
          {:status 200 :body {:token access :refreshToken refresh :csrfToken new-csrf}})))))

(defn csrf-handler
  "Handles CSRF token generation."
  [req]
  (let [action (get-in req [:path-params :action])
        username (get-in req [:identity :username])]
    (log/info "Generating CSRF token for action" {:action action :username username})
    {:status 200 :body {:csrfToken (generate-csrf @ds username action)}}))

(defn register-handler
  "Handles user registration."
  [req]
  (let [{:keys [username password email csrfToken]} (:body-params req)
        username (sanitize username)
        email (sanitize email)
        ip (:remote-addr req)]
    (log/info "Processing registration request" {:username username :email email :ip ip})
    (cond
      (not (and (valid-username? username)
                (valid-password? password)
                (valid-email? email)))
      (do
        (log/warn "Invalid registration input" {:username username :email email :ip ip})
        {:status 400 :body {:error "Invalid input: username (3-30 chars, alphanumeric, underscore, hyphen), password (8+ chars, uppercase, digit, special char), or email"}})
      (not (validate-csrf @ds csrfToken nil "register"))
      (do
        (log/warn "Invalid CSRF token for registration" {:username username :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})
      (user-exists? @ds username email)
      (do
        (log/warn "Username or email already exists" {:username username :email email :ip ip})
        {:status 409 :body {:error "Username or email already exists"}})
      :else
      (let [hashed (hashers/derive password {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
        (jdbc/with-transaction [tx @ds]
          (create-user tx username hashed email)
          (log/info "User registered successfully" {:username username :email email :ip ip})
          (audit tx "register" username ip {:email email}))
        {:status 201 :body {:message "User registered successfully"}}))))

(defn login-handler
  "Handles user login."
  [req]
  (let [{:keys [username password csrfToken]} (:body-params req)
        ip (:remote-addr req)]
    (log/info "Processing login request" {:username username :ip ip})
    (or (check-login-rate-limit username ip)
        (validate-login-input username password csrfToken ip)
        (authenticate-user @ds username password ip))))

(defn refresh-handler
  "Handles token refresh."
  [req]
  (let [{:keys [refreshToken csrfToken]} (:body-params req)
        ip (:remote-addr req)]
    (log/info "Processing token refresh request" {:ip ip})
    (cond
      (not refreshToken)
      (do
        (log/warn "Missing refresh token" {:ip ip})
        {:status 400 :body {:error "Invalid input"}})
      (my-get (str "blacklist:" refreshToken))
      (do
        (log/warn "Blacklisted refresh token" {:ip ip})
        {:status 401 :body {:error "Blacklisted token"}})
      :else
      (let [claims (unsign-token refreshToken)]
        (if-not claims
          (do
            (log/warn "Invalid or expired refresh token" {:ip ip})
            {:status 401 :body {:error "Invalid/expired refresh token"}})
          (let [username (:username claims)
                db-v (get-db-token-version @ds username)]
            (cond
              (not (= (:token_version claims) db-v))
              (do
                (log/warn "Invalid token version for refresh" {:username username :ip ip})
                {:status 401 :body {:error "Invalid token version"}})
              (not (validate-csrf @ds csrfToken username "refresh"))
              (do
                (log/warn "Invalid CSRF token for refresh" {:username username :ip ip})
                {:status 401 :body {:error "Invalid/missing CSRF token"}})
              :else
              (let [new-access (sign-token {:username username :token_version db-v} (:token-expiry config))
                    new-refresh (sign-token {:username username :token_version db-v} (:refresh-token-expiry config))
                    ttl (- (:exp claims) (quot (current-ms) 1000))]
                (my-set-ex (str "blacklist:" refreshToken) "1" ttl)
                (log/info "Token refreshed successfully" {:username username :ip ip})
                {:status 200 :body {:token new-access :refreshToken new-refresh}}))))))))

(defn logout-handler
  "Handles user logout."
  [req]
  (let [csrf (get-in req [:headers "x-csrf-token"])
        username (get-in req [:identity :username])
        claims (:claims req)
        token (extract-token req)
        ip (:remote-addr req)]
    (log/info "Processing logout request" {:username username :ip ip})
    (if-not (validate-csrf @ds csrf username "logout")
      (do
        (log/warn "Invalid CSRF token for logout" {:username username :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})
      (do
        (update-user-token-version @ds username)
        (let [ttl (- (:exp claims) (quot (current-ms) 1000))]
          (my-set-ex (str "blacklist:" token) "1" ttl))
        (log/info "Logout successful" {:username username :ip ip})
        (audit @ds "logout" username ip {})
        {:status 200 :body {:message "Logged out successfully"}}))))

(defn forgot-handler
  "Handles password reset requests."
  [req]
  (let [{:keys [email csrfToken]} (:body-params req)
        email (sanitize email)
        ip (:remote-addr req)]
    (log/info "Processing forgot password request" {:email email :ip ip})
    (cond
      (not (valid-email? email))
      (do
        (log/warn "Invalid email for password reset" {:email email :ip ip})
        {:status 400 :body {:error "Invalid input"}})
      (not (validate-csrf @ds csrfToken nil "forgot-password"))
      (do
        (log/warn "Invalid CSRF token for password reset" {:email email :ip ip})
        {:status 401 :body {:error "Invalid/missing CSRF token"}})
      :else
      (let [user (find-user-by-email @ds email)]
        (if user
          (let [token (str (java.util.UUID/randomUUID))
                expires (java.sql.Timestamp. (+ (current-ms) (* (:password-reset-expiry config) 1000)))]
            (insert-password-reset @ds token (:username user) expires)
            (log/info "Password reset token generated" {:username (:username user) :email email :ip ip})
            (audit @ds "password_reset_requested" (:username user) ip {:email email})
            {:status 200 :body {:message "If the email exists, a reset link has been sent" :resetToken token}})
          (do
            (log/info "Password reset requested for non-existent email" {:email email :ip ip})
            {:status 200 :body {:message "If the email exists, a reset link has been sent"}}))))))

(defn reset-handler
  "Handles password reset with a token."
  [req]
  (let [{:keys [token newPassword csrfToken]} (:body-params req)
        ip (:remote-addr req)]
    (log/info "Processing password reset request" {:ip ip})
    (cond
      (not (and token (valid-password? newPassword)))
      (do
        (log/warn "Invalid input for password reset" {:ip ip})
        {:status 400 :body {:error "Invalid input"}})
      :else
      (let [reset (find-password-reset @ds token)]
        (cond
          (not reset)
          (do
            (log/warn "Invalid or expired password reset token" {:ip ip})
            {:status 401 :body {:error "Invalid/expired reset token"}})
          (not (validate-csrf @ds csrfToken (:username reset) "reset-password"))
          (do
            (log/warn "Invalid CSRF token for password reset" {:username (:username reset) :ip ip})
            {:status 401 :body {:error "Invalid/missing CSRF token"}})
          :else
          (let [hashed (hashers/derive newPassword {:alg :bcrypt+sha512 :iterations (:bcrypt-rounds config)})]
            (jdbc/with-transaction [tx @ds]
              (update-user-password tx (:username reset) hashed)
              (delete-password-reset tx token)
              (log/info "Password reset successful" {:username (:username reset) :ip ip})
              (audit tx "password_reset" (:username reset) ip {}))
            {:status 200 :body {:message "Password reset successfully"}}))))))

(defn health-handler
  "Handles health check requests."
  [_]
  (log/info "Processing health check request")
  (let [db-ok (try
                (jdbc/execute! @ds [(:test-connection sql-queries)])
                (log/debug "Database health check passed")
                true
                (catch java.sql.SQLException e
                  (log/error "Database health check failed" {:error (.getMessage e)})
                  false))
        redis-ok (try
                   (wcar* (car/ping))
                   (log/debug "Redis health check passed")
                   true
                   (catch Exception e
                     (log/error "Redis health check failed" {:error (.getMessage e)})
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
        rate-limit-size (count (wcar* (car/keys "rate:*")))
        pool-stats (let [hikari-pool (.getHikariPoolMXBean ^HikariDataSource @ds)]
                     (.getTotalConnections hikari-pool))]
    (log/info "Health check completed" {:db-ok db-ok :redis-ok redis-ok :jwt-ok jwt-ok :rate-limit-size rate-limit-size :pool-stats pool-stats})
    (if (and db-ok jwt-ok)
      {:status 200 :body {:status "ok"
                          :components {:database (if db-ok "ok" "error")
                                       :redis (if redis-ok "ok" "error")
                                       :jwt (if jwt-ok "ok" "error")
                                       :rateLimitSize rate-limit-size
                                       :poolStats pool-stats}}}
      {:status 503 :body {:status "error"
                          :components {:database (if db-ok "ok" "error")
                                       :redis (if redis-ok "ok" "error")
                                       :jwt (if jwt-ok "ok" "error")
                                       :rateLimitSize rate-limit-size
                                       :poolStats pool-stats}}})))

;; App
(def ^:private muuntaja (m/create m/default-options))

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
                           (cors-middleware handler (:allowed-origins config)))]}})
   (ring/create-default-handler
     {:not-found (fn [_]
                   (log/warn "Route not found")
                   {:status 404 :headers {"Content-Type" "application/json"} :body (cheshire/encode {:error "Not found"})})})))

;; Server
(def ^:private server (atom nil))
(def ^:private cleanup-rate-thread (atom nil))
(def ^:private cleanup-blacklist-thread (atom nil))

(defn start
  "Starts the auth server."
  []
  (log/info "Starting auth server")
  (init-db)
  (init-redis)
  (reset! cleanup-rate-thread (future (while true (Thread/sleep (:rate-limit-cleanup-interval config)) (cleanup-rate-limits))))
  (log/info "Started rate limit cleanup thread")
  (reset! cleanup-blacklist-thread (future (while true (Thread/sleep (:blacklist-cleanup-interval config)) (cleanup-blacklist))))
  (log/info "Started blacklist cleanup thread")
  (reset! server (jetty/run-jetty #'app {:port (:port config) :join? false}))
  (log/info "Auth server started" {:port (:port config)}))

(defn stop
  "Stops the auth server."
  []
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

(defn -main
  "Main entry point for the auth server."
  [& _]
  (log/info "Main function invoked")
  (.addShutdownHook (Runtime/getRuntime) (Thread. stop))
  (start))

(comment
  (set-log-level nil :info)
  (set-log-level "auth-server" :debug)
  (stop)
  (start))
