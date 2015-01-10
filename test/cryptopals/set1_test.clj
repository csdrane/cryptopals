(ns cryptopals.set1-test
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [cryptopals.set1 :as cp])
  (:import [javax.xml.bind DatatypeConverter]
           [org.apache.commons.codec.binary Base64]))

(def base-dir (System/getProperty "user.dir"))
(def prob-4-data (str/split (slurp (str base-dir "/test/cryptopals/4.txt")) #"\s+"))
(def prob-5-text (.getBytes (String. "Burning 'em, if you ain't quick and nimble I go\ncrazy when I hear a cymbal")))
(def prob-6-data-loc (str base-dir "/test/cryptopals/6.txt"))
(def prob-6-data (cp/decode-base64 (cp/slurp-bytes prob-6-data-loc)))
(cp/xor-array prob-5-text 53)
(deftest hex->base64
  (is (= (cp/hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))

(deftest decode-base64
  (is (= (cp/decode-base64-string "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
         "I'm killing your brain like a poisonous mushroom")))

(deftest base-10-to-hex
  (is (= (cp/base-10-to-hex 15) "0f"))
  (is (= (cp/base-10-to-hex 16) "10"))
  (is (= (cp/base-10-to-hex 17) "11")))

(deftest decode-xor-string
  (is (= (cp/decode-xor-byte (cp/parse-hex-string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" ) 16r58) "Cooking MC's like a pound of bacon"))
  (is (= (cp/decode-xor-byte (cp/parse-hex-string "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f") 53) "Now that the party is jumping\n")))

(deftest find-xored-string
  (is (= (cp/find-xored-string (map cp/parse-hex-string prob-4-data))
         "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")))

(deftest find-xored-single-byte-key
  (is (= (cp/find-xored-single-byte-key (cp/parse-hex-string "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")) "Now that the party is jumping\n")))

(deftest hamming-distance
  (is (= (cp/hamming-distance "this is a test" "wokka wokka!!!")
         37)))

(deftest repeating-xor
  (is (= (cp/repeating-xor prob-5-text "ICE")
         "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c4f2a3124333a653e2b2027630c692b20283165286326302e27282f")))

(deftest get-chunks
  (is (= (cp/get-chunks "123abcxyz[]\\" 3)
         '((\[ \] \\) (\x \y \z) (\a \b \c) (\1 \2 \3)))))

(deftest chunk-distance
  (is (> 0.10  (Math/abs ( - 2.33 (cp/chunk-distance '((\[ \] \\) (\x \y \z) (\a \b \c) (\1 \2 \3))))))))

(deftest get-key-size-rotating-xor
  (is (= (cp/get-key-size-rotating-xor prob-6-data) 29 )))

(deftest transpose
  (is (= (cp/transpose-data '((1 2 3) (4 5 6) (7 8 9))) '((1 4 7) (2 5 8) (3 6 9)))))

;; (for [x (range 2 100)]
;;   (let [text (cp/xor-array (first (cp/transpose-data (cp/get-chunks problem-6-data 29))) x)
;;         ic (cp/ic text)
;;         m {:key x :score ic :norm-score (Math/abs (- ic 1.75))}]
;;     (sort-by :norm-score > m)))


(Math/abs -0.5)
