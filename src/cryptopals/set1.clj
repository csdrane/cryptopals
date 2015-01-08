(ns cryptopals.set1
  (:require [clojure.string :as str])
  (:import (java.util Base64 BitSet)
           (java.math BigInteger)))

(defn hex->base64 [^String s]
  "Given hex string, returns equivalent base64 string."
  (.encodeToString (Base64/getEncoder) (.toByteArray (BigInteger. s 16))))

(defn base64->string [^String s]
  "Given base64 string, returns ASCII string."
  (let [base64 (apply str (str/split-lines s))]
    (String. (.decode (Base64/getDecoder) base64))))

(defn hex->binary [^String s]
  "Given hex string, returns binary string."
  (.toString (BigInteger. s 16) 2))

(def characters
  (concat (map char (range 48 58)) (map char (range 97 103))))

(def conversion-table
  (zipmap
   characters
   (range)))

(defn base-10-to-hex
  "Given integer, returns string of one hex byte."
  [^Integer number]
  (let [hexnum (loop [num number
                   acc []]
              (if (zero? num)
                (clojure.string/join (reverse acc))
                (recur (int (/ num 16))
                       (conj acc (nth characters (mod num 16))))))]
    (if (= 0 (count hexnum))
      (str "0" hexnum)
      hexnum)))

(defn fixed-xor [^String s1 ^String s2]
  "Given two hex byte strings, returns XOR as string"
  (.toString (.xor (BigInteger. s1 16) (BigInteger. s2 16)) 16))

(defn score-text [^String text]
  "Given string, returns hash map of character frequency."
  (sort-by val >
           (letfn [(helper [text counts]
                     (if (empty? text)
                       counts
                       (let [letter (first text)
                             updated-counts
                             (update-in counts [letter] (fnil inc 0))]
                         (helper (rest text) updated-counts))))]
             (helper text {}))))

(score-text "has been XORd against a single character. Find the key, decrypt the message. You can do this by hand. But dont: write code to do it for you. How? Devise some method for scoring a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.")

(defn big-xor [^String string ^String byte]
  "Given byte string and hex string, return XOR of byte applied to entire string."
  (do #_(println string byte)
      (letfn [(helper [input byte output]
                (if (empty? input)
                  output
                  (do #_(println input byte output)
                      (let [xored-byte (bit-xor (Integer/parseInt (subs input 0 2) 16) byte)
                            new-input (apply str (drop 2 input))
                            new-output (conj output xored-byte)]
                        (do
                          #_(println xored-byte new-input new-output)
                          (helper new-input byte new-output))))))]
        (helper string byte []))))

(defn decode-xor-string [^String s ^String k]
  "Takes hex string and hex byte, calls big-xor, and returns decoded ASCII string."
  (apply str (map (comp char #(Integer/parseInt %) str)
        (big-xor s k))))

(def actual-words (set
                   (str/split
                    (slurp "/usr/share/dict/words")
                    #"\s+")))

(defn word-score [^String decoded-bytes]
  "Takes decoded byte string, returns number of English words identified in decrypted byte string."
  (do #_(println bytes)
      (let [decoded-words (str/split decoded-bytes #"\s+")
            score (reduce (fn [init coll]
                            (if (actual-words coll)
                              (inc init)
                              init)) 0 decoded-words)]
        score)))

(defn find-xored-single-byte-key [crypt-text]
  "Take vector of byte strings and iterates through keys, returning the best match. "
  (let [key-upper-bound 100]
    (letfn [(helper [key decrypted-text score]
              (if (> key key-upper-bound)
                decrypted-text
                (let [new-decrypted-text (decode-xor-string crypt-text key)
                      new-score (word-score new-decrypted-text )
                      best-decrypted-text (if (> new-score score) new-decrypted-text decrypted-text)
                      best-score (max new-score score)]
                  (helper (inc key) best-decrypted-text best-score))))]
      (helper 1 "" 0))))

(defn find-xored-string [crypt-text]
  "Given n lines of hex strings, returns sole XOR encoded line."
  (letfn [(helper [crypt-text candidate-text score]
            (if (empty? crypt-text)
              candidate-text
              (let [new-candidate-text (first crypt-text)
                    new-score (word-score (find-xored-single-byte-key new-candidate-text))
                    best-candidate-text (if (> new-score score) new-candidate-text candidate-text)
                    best-score (max score new-score)]
                (helper (rest crypt-text) best-candidate-text best-score))))]
    (helper crypt-text "" 0)))

(defn repeating-xor [string key]
  (letfn [(helper [string key coll]
            (if (empty? string)
              coll
              (let [xored-byte (base-10-to-hex (apply bit-xor (map int [(first string) (first key)])))]
                (helper (rest string) (drop 1 (take 4 (cycle key))) (str coll xored-byte)))))]
    (helper string key "")))

(def prob-5-text1 "Burning 'em, if you ain't quick and nimble I go\ncrazy when I hear a cymbal")

(repeating-xor prob-5-text1 "ICE")

;; 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c4f2a3124333a653e2b2027630c692b20283165286326302e27282f

(defn hamming-distance [a b]
  (letfn [(xor-letter [a b]
            (reduce (fn [init coll]
                      (if (= \1 coll)
                        (inc init)
                        init)) 0 (Long/toBinaryString (apply bit-xor (map int [a b])))))]
    (apply + (map xor-letter a b))))

(hamming-distance "this is a test" "wokka wokka!!!")
;; 37

(defn get-chunks [data key-size n]
  "Given a string of data, returns a list of n key-sized chunks"
  (loop [data data
         n n
         coll '()]
    (if (or (empty? data)
            (= 0 n))
      coll
      (recur (drop key-size data) (dec n) (cons (take key-size data) coll)))))

(defn chunk-distance [data key-size n]
  (let [avg (fn [& args] (/ (apply + args) (count args)))
        chunks (get-chunks data key-size n)
        distances (reduce (fn [init coll]
                            (conj init (apply hamming-distance coll)))
                          [] (partition 2 chunks))]
    (apply avg distances)))

(defn break-rotating-xor [crypt-text]
  (let [key-max-size 40
        chunk-number 8]                 ; should be even number
    (letfn [(helper [key-size crypt-text lowest-distance]
              (let [chunks (get-chunks crypt-text key-size chunk-number)]
                (if (< key-size key-max-size)
                  (let [distance (chunk-distance crypt-text key-size chunk-number)
                        new-lowest-distance (if (< distance (:distance lowest-distance))
                                              {:key-size key-size
                                               :distance distance}
                                              lowest-distance)]
                    (do #_(println key-size (float distance)) (helper (inc key-size) crypt-text new-lowest-distance)))
                  lowest-distance)))]
      (helper 2 crypt-text {:key-size 2 :distance Integer/MAX_VALUE}))))

(defn chunk-data [data key-size]
  "Return key-sized chunks for a block of data."
  (partition key-size data))

(defn transpose-data [chunks]
  (apply map str chunks))

;;; this is wrong!
(defn decrypt-chunks [chunks]
  (for [chunk chunks]
    (find-xored-string (apply str (map (comp base-10-to-hex int) chunk)))))

;; (find-xored-string (apply str (map (comp base-10-to-hex int) (first (transpose-data (chunk-data (base64->string (slurp "http://cryptopals.com/static/challenge-data/6.txt")) 2))))))
