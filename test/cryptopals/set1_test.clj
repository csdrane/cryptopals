(ns cryptopals.set1-test
  (:require [clojure.test :refer :all]
            [clojure.string :as str]
            [cryptopals.set1 :as cp]))

(def base-dir (System/getProperty "user.dir"))
(def problem-4-data (str/split (slurp (str base-dir "/test/cryptopals/4.txt")) #"\s+"))
(def problem-6-data (cp/base64->string (slurp (str base-dir "/test/cryptopals/6.txt"))))
(def prob-5-text1 "Burning 'em, if you ain't quick and nimble I go\ncrazy when I hear a cymbal")

(deftest hex->base64
  (is (= (cp/hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))

(deftest base64->string
  (is (= (cp/base64->string "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
         "I'm killing your brain like a poisonous mushroom")))

(deftest base-10-to-hex
  (is (= (cp/base-10-to-hex 15) "0f"))
  (is (= (cp/base-10-to-hex 16) "10"))
  (is (= (cp/base-10-to-hex 17) "11")))

(deftest decode-xor-string
  (is (= (cp/decode-xor-string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" 16r58) "Cooking MC's like a pound of bacon"))
  (is (= (cp/decode-xor-string "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f" 53)
         "Now that the party is jumping\n")))

(deftest find-xored-string
  (is (= (cp/find-xored-string problem-4-data)
         "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")))

(deftest find-xored-single-byte-key
  (is (= (cp/find-xored-single-byte-key "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f") "Now that the party is jumping\n")))

(deftest hamming-distance
  (is (= (cp/hamming-distance "this is a test" "wokka wokka!!!")
         37)))

(deftest repeating-xor
  (is (= (cp/repeating-xor prob-5-text1 "ICE")
         "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c4f2a3124333a653e2b2027630c692b20283165286326302e27282f")))

(deftest get-chunks
  (is (= (cp/get-chunks "123abcxyz[]\\" 3 4)
         '((\[ \] \\) (\x \y \z) (\a \b \c) (\1 \2 \3)))))

(deftest chunk-distance
  (is (> 0.10  (Math/abs ( - 4.6666665 (cp/chunk-distance '((\[ \] \\) (\x \y \z) (\a \b \c) (\1 \2 \3)) 3))))))

(for [key (range 2 40)]
  (do (println key "-" (cp/data-distance problem-6-data key))))

(cp/data-distance '(1 2 2 3 3 4 4 5) 2)
