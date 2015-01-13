(ns cryptopals.set2-test
  (:require [clojure.test :refer :all]
            [cryptopals.set2 :as cp])
  (:import [java.util Arrays]))

(deftest pad
  (is (Arrays/equals (cp/pad "YELLOW SUBMARINE" 20)
                     (byte-array 20 (concat (.getBytes (String. "YELLOW SUBMARINE"))
                                            '(04 04 04 04))))))

(deftest Problem-1.10
  (is (= (apply str (take 12 (apply str (map char (map identity (cp/decrypt-AES-CBC "YELLOW SUBMARINE" cp/prob-10-data))))))
         "I'm back and") ))

;; (deftest attack-ecb
;;   (is (Arrays/equals (cp/attack-ecb 16)
;;                      (byte-array (concat (.getBytes (apply str (repeat 159 \A))) '(0))))))

(deftest get-first-byte
  (is (= (cp/get-first-byte) 82)))

