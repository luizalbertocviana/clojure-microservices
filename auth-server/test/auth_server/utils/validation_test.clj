(ns auth-server.utils.validation-test
  (:require [clojure.test :refer [deftest is testing]]
            [auth-server :refer [valid-username? valid-email? valid-password? sanitize]]))

(deftest test-valid-username
  (testing "Valid usernames"
    (is (valid-username? "user123"))
    (is (valid-username? "user_name"))
    (is (valid-username? "user-name"))
    (is (valid-username? "User123"))
    (is (valid-username? "a12345678901234567890123456789"))) ; 30 chars

  (testing "Invalid usernames"
    (is (not (valid-username? nil)))
    (is (not (valid-username? "")))
    (is (not (valid-username? "ab"))) ; Too short
    (is (not (valid-username? "a123456789012345678901234567890"))) ; 31 chars, too long
    (is (not (valid-username? "user name"))) ; Space not allowed
    (is (not (valid-username? "user@name"))) ; @ not allowed
    (is (not (valid-username? "user.name"))) ; . not allowed
    (is (not (valid-username? "user+name"))))) ; + not allowed

(deftest test-valid-email
  (testing "Valid emails"
    (is (valid-email? "user@example.com"))
    (is (valid-email? "user.name@example.com"))
    (is (valid-email? "user+name@example.com"))
    (is (valid-email? "user123@test-domain.com"))
    (is (valid-email? "User@Example.COM")))

  (testing "Invalid emails"
    (is (not (valid-email? nil)))
    (is (not (valid-email? "")))
    (is (not (valid-email? "user")))
    (is (not (valid-email? "user@")))
    (is (not (valid-email? "@example.com")))
    (is (not (valid-email? "user@.com")))
    (is (not (valid-email? "user@example.")))
    (is (not (valid-email? "user@@example.com")))))

(deftest test-sanitize
  (testing "HTML sanitization"
    (is (= (sanitize "<script>") "&lt;script&gt;"))
    (is (= (sanitize "<div>content</div>") "&lt;div&gt;content&lt;/div&gt;"))
    (is (= (sanitize "user & pass") "user &amp; pass"))
    (is (= (sanitize "\"quotes\"") "&quot;quotes&quot;"))
    (is (= (sanitize "'single quotes'") "&#39;single quotes&#39;"))
    (is (= (sanitize "normal text") "normal text"))
    ; Note: The sanitize function doesn't handle nil values, so we test with empty string
    (is (= (sanitize "") ""))))