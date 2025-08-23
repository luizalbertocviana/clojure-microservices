(ns auth-server.utils.token-test
  (:require [clojure.test :refer [deftest is testing]]
            [auth-server :as auth]
            [next.jdbc :as jdbc]))

;; Mock the database dependency for CSRF functions
(def mock-db-results (atom []))
(def mock-db-executions (atom []))

(deftest test-sign-and-unsign-token
  (testing "Valid token signing and verification"
    (let [claims {:username "testuser"}
          expiry 3600
          token (auth/sign-token claims expiry)
          decoded (auth/unsign-token token)]
      (is (some? decoded))
      (is (= "testuser" (:username decoded)))))
  
  (testing "Token expiration"
    (let [claims {:username "testuser"}
          expiry -1  ; Expired token
          token (auth/sign-token claims expiry)
          decoded (auth/unsign-token token)]
      (is (nil? decoded)))))

(deftest test-generate-csrf
  (testing "CSRF token generation"
    ;; Mock the database functions
    (with-redefs [jdbc/execute! (fn [ds sql-params]
                                  (swap! mock-db-executions conj sql-params)
                                  [])]
      (reset! mock-db-executions [])
      (let [username "testuser"
            action "login"
            token (auth/generate-csrf username action)]
        (is (string? token))
        (is (= 1 (count @mock-db-executions)))
        (is (= "INSERT INTO csrf_tokens (token, username, action, expires_at) VALUES (?, ?, ?, ?)"
               (first (first @mock-db-executions))))))))

(deftest test-validate-csrf
  (testing "Valid CSRF token validation"
    ;; Mock the database functions
    (with-redefs [jdbc/execute-one! (fn [ds sql-params]
                                      (first @mock-db-results))
                  jdbc/execute! (fn [ds sql-params]
                                  (swap! mock-db-executions conj sql-params)
                                  [])]
      (reset! mock-db-results [{:token "test-token"
                                :username "testuser"
                                :action "login"
                                :expires_at (java.sql.Timestamp. (+ (System/currentTimeMillis) 3600000))}])
      (reset! mock-db-executions [])
      (let [valid (auth/validate-csrf "test-token" "testuser" "login")]
        (is (true? valid))
        ;; Check that we executed the DELETE query
        (is (= 1 (count (filter #(= "DELETE FROM csrf_tokens WHERE token = ?" (first %)) 
                                @mock-db-executions)))))))

  (testing "Invalid CSRF token validation"
    ;; Mock the database functions
    (with-redefs [jdbc/execute-one! (fn [ds sql-params]
                                      (first @mock-db-results))
                  jdbc/execute! (fn [ds sql-params]
                                  (swap! mock-db-executions conj sql-params)
                                  [])]
      (reset! mock-db-results []) ; No results means invalid token
      (reset! mock-db-executions [])
      (let [valid (auth/validate-csrf "invalid-token" "testuser" "login")]
        (is (false? (boolean valid))) ; Convert nil to false for the test
        ;; Check that we did NOT execute the DELETE query
        (is (= 0 (count (filter #(= "DELETE FROM csrf_tokens WHERE token = ?" (first %)) 
                                @mock-db-executions))))))))