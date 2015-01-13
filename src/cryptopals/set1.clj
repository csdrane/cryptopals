(ns cryptopals.set1
  (:require [cryptopals.text :as text]
            [clojure.string :as str])
  (:import [java.lang Byte]
           [java.util BitSet]
           [java.math BigInteger]
           [java.security SecureRandom]
           [javax.crypto Cipher KeyGenerator]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]
           [javax.xml.bind DatatypeConverter]
           [org.apache.commons.codec.binary Base64]))

(def base-dir (System/getProperty "user.dir"))

(def characters
  (concat (map char (range 48 58)) (map char (range 97 103))))

(def conversion-table
  (zipmap
   characters
   (range)))

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
                            (if (text/actual-words coll)
                              (inc init)
                              init)) 0 decoded-words)]
        score)))

(defn find-xored-single-byte-key [crypt-text]
  "Take vector of byte arrays and iterates through keys, returning the best match. "
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

(defn find-xored-string [crypt-text]
  "Given n lines of hex strings, returns sole XOR encoded line."
  (letfn [(helper [crypt-text candidate-text score]
            (if (empty? crypt-text)
              (apply str (map base-10-to-hex candidate-text))
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
              (let [xored-byte (base-10-to-hex (apply xor (map int [(first string) (first key)])))]
                (helper (rest string) (drop 1 (take 4 (cycle key))) (str coll xored-byte)))))]
    (helper string key "")))

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

(defn number-chunks [data-length key-size]
  (/ data-length key-size))

(defn get-chunks [^String data ^Integer key-size]
  "Given a string of data, returns a list of 2n key-sized chunks. (2n because the data will be a string representing bytes"
  (loop [data (strip-data data key-size)
         n (number-chunks (count data) key-size)
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

(defn data-distance [data key-size]
  (chunk-distance (get-chunks data key-size)))

(defn get-key-size-rotating-xor [crypt-text]
  (get (first (sort-by :distance <
                   (let [key-max-size 40]
                     (for [key-size (range 1 (inc key-max-size))]
                       {:key-size key-size :distance (data-distance crypt-text key-size)}))))
       :key-size))

(defn transpose-data [chunks]
  (apply map list chunks))

(defn english-probability [text]
  (let [text (str/upper-case text)
        letters (into #{} (keys text/english-frequency))
        text-letters (filter letters text)
        non-letters (filter #(not (letters %)) text)
        spaces (filter #(= % \space) non-letters)
        non-spaces (filter #(not= % \space) non-letters)
        error (fn [numerator denominator average-frequency]
                (Math/abs (- (float (/ (count numerator)
                                       (count denominator)))
                             average-frequency)))
        space-error (error spaces text 0.15)
        punc-error (error non-spaces text 0.02)
        letter-error (reduce (fn [i [letter frequency]]
                                (+ i (* frequency
                                        (error (filter #{letter} letters)
                                               text-letters
                                               frequency)))) 0.0 text/english-frequency)]
    (max (- 1 (+ punc-error space-error letter-error)) 0.0)))

(defn get-decryption-key [scoring-method transposed-data]
  (letfn [(get-byte [cipher-text]
            (first
             (sort-by :score >
                      (for [x (range 32 128)]
                        (let [text (apply str (map char (xor-array cipher-text x)))
                              score (scoring-method text)
                              m {:key x :score score}]
                          m)))))]
    (apply str (map (comp char :key get-byte)
                    transposed-data))))

(defn decrypt-with-key [text decrypt-key]
  (loop [text text
         key decrypt-key
         coll ""]
    (if (empty? text)
      coll
      (recur (rest text) (take (count key) (drop 1 (cycle key)))
             (str coll (char (xor (first text) (int (first key)))))))))

(defn decrypt-AES-ECB [key ciphertext]
  (let [cipher (. Cipher getInstance "AES/ECB/NoPadding")
        key (.getBytes (String. key))
        rawkey (new SecretKeySpec key "AES")]
    (do (. cipher init (Cipher/DECRYPT_MODE) rawkey)
        (. cipher doFinal ciphertext))))

(defn count-repeats [ciphertext]
  "Returns how many times the first 16 bytes occur in cipher text."
  (dec (let [init-16 (take 16 ciphertext)]
     (loop [ciphertext ciphertext
            ctr 0]
       (if (empty? ciphertext)
         ctr
         (let [next-16  (take 16 ciphertext)
               new-ctr (if (= init-16 next-16)
                         (inc ctr)
                         ctr)]
           (recur (drop 1 ciphertext) new-ctr)))))))

(defn detect-repeats [data]
  "This is going to double count each instance of a repeat."
  (loop [data data
         repeats 0
         ctr 0]
    (let [data-len (count data)
          cycle-data (drop 16
                           (take (+ data-len 16)
                                 (cycle data)))
          stop-when (/ data-len 16)]
      (if (= stop-when ctr)
        repeats
        (recur cycle-data
               (+ repeats
                  (count-repeats data))
               (inc ctr))))))



