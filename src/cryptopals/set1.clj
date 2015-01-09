(ns cryptopals.set1
  (:require [clojure.string :as str])
  (:import [java.lang Byte]
           [java.util BitSet]
           [java.math BigInteger]
           [javax.xml.bind DatatypeConverter]
           [org.apache.commons.codec.binary Base64]))

(def characters
  (concat (map char (range 48 58)) (map char (range 97 103))))

(def conversion-table
  (zipmap
   characters
   (range)))

(def actual-words (set
                   (str/split
                    (slurp "/usr/share/dict/words")
                    #"\s+")))

(defn avg [& args] (/ (apply + args) (count args)))

(defn slurp-bytes [path]
  "Reads file at path and returns Java byte array."
  (let [f (java.io.File. path)
        ary (byte-array (.length f))
        is (java.io.FileInputStream. f)]
    (.read is ary)
    (.close is)
    ary))

(defn hex->base64 [^String s]
  "Given hex string, returns equivalent base64 string."
  (Base64/encodeBase64String (.toByteArray (BigInteger. s 16))))

(defn decode-base64 [byte-array]
  "Given base64 byte-array, returns decoded byte-array."
  (Base64/decodeBase64 byte-array))

(defn decode-base64-string [^String s]
  (String. (decode-base64 (.getBytes (String. s)))))

(defn parse-hex-string [string] 
  (letfn [(abs [x] (if (neg? x) (* -1 x)) x)]
    (map #(if (<= % 0)
            (+ (abs %) 128)
            %)
         (DatatypeConverter/parseHexBinary string))))

(defn base-10-to-hex
  "Given integer, returns string of one hex byte."
  [^Integer number]
  (let [hexnum (loop [num number
                   acc []]
              (if (zero? num)
                (clojure.string/join (reverse acc))
                (recur (int (/ num 16))
                       (conj acc (nth characters (mod num 16))))))]
    (if (= 1 (count hexnum))
      (str "0" hexnum)
      hexnum)))

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

(def xor bit-xor)

(defn xor-array [byte-array byte]
  "Given Java byte and byte[], returns XOR of singular byte applied to each byte in byte[]. Function returns ordinal values but can be converted to binary by mapping Integer/toBinaryString" 
  (map xor byte-array (repeat byte)))

(defn decode-xor-byte [s k]
  "Takes hex string and hex byte, calls xor-array, and returns decoded text as ASCII."
  (apply str (map char (xor-array s k))))

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
                (let [new-decrypted-text (decode-xor-byte crypt-text key)
                      new-score (word-score new-decrypted-text )
                      best-decrypted-text (if (> new-score score) new-decrypted-text decrypted-text)
                      best-score (max new-score score)]
                  (helper (inc key) best-decrypted-text best-score))))]
      (helper 1 "" 0))))

;; (defn repeating-xor [string key]
;;   (letfn [(helper [string key coll]
;;             (if (empty? string)
;;               coll
;;               (let [xored-byte (base-10-to-hex (apply bit-xor (map int [(first string) (first key)])))]
;;                 (helper (rest string) (drop 1 (take 4 (cycle key))) (str coll xored-byte)))))]
;;     (helper string key "")))

(defn hamming-distance [a b]
  (letfn [(xor-letter [a b]
            (reduce (fn [init coll]
                      (if (= \1 coll)
                        (inc init)
                        init)) 0 (Long/toBinaryString (apply xor (map int [a b])))))]
    (apply + (map xor-letter a b))))

(defn strip-data [data key-size]
  {:docstring "Takes string of data and key size, returns data stripped to make even pairs for given key-size."
   :post [(even? (count %))]} 
  (drop-last (rem (count data) (* 2 key-size)) data))

(defn get-chunks [^String data ^Integer key-size ^Integer n]
  "Given a string of data, returns a list of 2n key-sized chunks. (2n because the data will be a string representing bytes"
  (loop [data (strip-data data key-size)
         n n
         coll '()]
    (if (or (empty? data)
            (= 0 n))
      coll
      (recur (drop key-size data) (dec n) (cons (take key-size data) coll)))))

(defn chunk-distance [chunks]
  {:pre [(even? (count chunks))]
   :docstring  "Takes list of even number of equally sized lists, returns average Hamming Distance."}
  (let [key-size (count (first chunks))
        chunks (partition 2 chunks)
        normalize (fn [x] (/ x key-size))
        distances (map normalize
                       (map (partial apply hamming-distance) chunks))
        average-distance (float (apply avg distances))]
    average-distance))

(defn number-chunks [data-length key-size]
  (/ data-length key-size))

(defn data-distance [data key-size]
  (chunk-distance (get-chunks data key-size
                              (number-chunks (count data) key-size))))

;; (defn break-rotating-xor [crypt-text]
;;   (let [key-max-size 40
;;         chunk-number 8]                 ; should be even number
;;     (letfn [(helper [key-size crypt-text lowest-distance]
;;               (let [chunks (get-chunks crypt-text key-size chunk-number)]
;;                 (if (< key-size key-max-size)
;;                   (let [distance (chunk-distance crypt-text key-size chunk-number)
;;                         new-lowest-distance (if (< distance (:distance lowest-distance))
;;                                               {:key-size key-size
;;                                                :distance distance}
;;                                               lowest-distance)]
;;                     (do #_(println key-size (float distance)) (helper (inc key-size) crypt-text new-lowest-distance)))
;;                   lowest-distance)))]
;;       (helper 2 crypt-text {:key-size 2 :distance Integer/MAX_VALUE}))))

(defn chunk-data [data key-size]
  "Return key-sized chunks for a block of data."
  (partition key-size data))

;; (defn transpose-data [chunks]
;;   (apply map str chunks))

;; ;;; this is wrong!
;; (defn decrypt-chunks [chunks]
;;   (for [chunk chunks]
;;     (find-xored-string (apply str (map (comp base-10-to-hex int) chunk)))))

;; (find-xored-string (apply str (map (comp base-10-to-hex int) (first (transpose-data (chunk-data (decode-base64 (slurp "http://cryptopals.com/static/challenge-data/6.txt")) 2))))))
