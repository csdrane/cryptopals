(ns cryptopals.set2
  (:require [cryptopals.set1 :as cp1])
  (:import [java.util Arrays]
           [javax.crypto Cipher KeyGenerator]
           [javax.crypto.spec SecretKeySpec]
           [java.security SecureRandom]
           [javax.xml.bind DatatypeConverter]))

(defn generate-key-aes []
  (let [keygen (KeyGenerator/getInstance "AES")
        random (new SecureRandom)]
    (do (.init keygen 128 random)
        (.generateKey keygen))))

(def prob-11-secret-key (.getEncoded (generate-key-aes)))
(def prob-11-secret-base64 (DatatypeConverter/parseBase64Binary"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))

(defn pad [pt blocksize]
  (let [len (count pt)
        pt-bytes (.getBytes (String. pt))
        pad-len (- blocksize (mod len blocksize))]
    (byte-array (+ len pad-len)
                (concat pt-bytes (repeat (int pad-len) pad-len)))))

(defn pad-bytes [pt-bytes blocksize]
  (let [len (count pt-bytes)
        pad-len (- blocksize (mod len blocksize))]
    (byte-array (+ len pad-len)
                (concat pt-bytes (repeat (int pad-len) pad-len)))))

(def IV (byte-array 16 (repeat 16 0)))

(def prob-10-data
  (let [decoded (cp1/decode-base64 (cp1/slurp-bytes (str cp1/base-dir "/test/cryptopals/10.txt")))]
    (byte-array (count decoded) decoded)))

(defn decrypt-AES-ECB [key ciphertext]
  (let [cipher (. Cipher getInstance "AES/ECB/NoPadding")
        rawkey (if-not (= (class key)
                          javax.crypto.spec.SecretKeySpec)
                 (new SecretKeySpec key "AES"))]
    (do (. cipher init (Cipher/DECRYPT_MODE) rawkey)
        (. cipher doFinal ciphertext))))

(defn encrypt-AES-ECB [key plaintext]
  (let [cipher (. Cipher getInstance "AES/ECB/NoPadding")
        rawkey (if-not (= (class key)
                          javax.crypto.spec.SecretKeySpec)
                 (new SecretKeySpec key "AES"))]
    (do (. cipher init (Cipher/ENCRYPT_MODE) rawkey)
        (. cipher doFinal plaintext))))

(defn encrypt-AES-CBC [key plaintext & iv]
  (let [iv (or iv (byte-array (map (fn [_] (rand-int 255)) (repeat 16 :foo))))]
    (letfn [(current-chunk [x] (Arrays/copyOfRange x 0 16))
            (helper [plaintext coll iv]
              (if (empty? plaintext)
                coll
                (let [chunk (current-chunk plaintext)
                      xor-block (byte-array 16 (map bit-xor iv chunk))
                      ecb-block (encrypt-AES-ECB key xor-block)
                      new-iv ecb-block]
                  (helper (Arrays/copyOfRange plaintext 16 (count plaintext))
                          (byte-array (+ 16 (count coll)) (concat coll ecb-block))
                          new-iv))))]
      (helper plaintext (byte-array 0) iv))))

(defn decrypt-AES-CBC [key plaintext]
  (letfn [(current-chunk [x] (Arrays/copyOfRange x 0 16))
          (helper [plaintext coll iv]
            (if (empty? plaintext)
              coll
              (let [chunk (current-chunk plaintext)
                    xor-block (cp1/decrypt-AES-ECB key chunk)
                    plaintext-block (byte-array 16 (map bit-xor iv xor-block))
                    new-iv chunk]
                (helper (Arrays/copyOfRange plaintext 16 (count plaintext))
                        (byte-array (+ 16 (count coll)) (concat coll plaintext-block))
                        new-iv))))]
    (helper plaintext (byte-array 0) IV)))

(defn encryption-oracle [input]
  (letfn [(random-bytes []
            (let [times (+ 5 (rand-int 6))]
              (byte-array (map (fn [_] (rand-int 255)) (repeat times :foo)))))]
    (let [header (random-bytes)
          footer (random-bytes)
          padded-plaintext (pad (byte-array (concat header (.getBytes input) footer)) 16)
          encrypt-random (condp = (rand-int 2)
                           0 encrypt-AES-ECB
                           1 encrypt-AES-CBC)]
      (encrypt-random (.getEncoded (generate-key-aes)) padded-plaintext))))

(cp1/detect-repeats (encryption-oracle "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
;; repeats = ECB
;; lackthereof = CBC

(defn ecb-oracle [user-input]
  "For problem 12"
  (encrypt-AES-ECB
   prob-11-secret-key
   (byte-array (pad-bytes
                (concat user-input prob-11-secret-base64)
                16))))

(map identity (ecb-oracle []))

(defn create-table [encryption-function padding-byte & [found-bytes]]
  {:docstring "Returns hash-map mapping byte-array one byte short of block size to resulting output."}
  (let [found-bytes (if (nil? (first found-bytes)) nil found-bytes)
        padding-len (- 15 (count found-bytes))
        padding-bytes (repeat padding-len padding-byte)
        initial-bytes (concat padding-bytes (if-not (empty? found-bytes) found-bytes))]
    (letfn [(to-vec [byte-array]
              (into [] (map identity byte-array)))]
      (into {} (for [last-byte (range 0 255)]
                 (let [bytes (byte-array (concat initial-bytes (list last-byte)))]
                   {(to-vec (take 16 (map identity (encryption-function bytes)))) (to-vec bytes)}))))))

; add another assertion for byte-pos + found-bytes?
(defn get-byte [byte-pos padding-byte & [found-bytes]]
  {:pre [(and (< 0 byte-pos 17)
              (integer? padding-byte))]}
  (let [padding-len (- 16 byte-pos)
        padding (repeat padding-len padding-byte)
        table (create-table ecb-oracle padding-byte (if-not (empty? found-bytes) found-bytes))
        bytes-for-oracle (byte-array padding)
        oracle-output (into [] (take 16 (ecb-oracle bytes-for-oracle)))]
    (get table oracle-output)))

(defn get-first-plaintext-block []
  (map identity
       (loop [pos 1
              found-bytes (vector-of :byte)]
         (if (= pos 17)
           found-bytes
           (let [new-byte (byte (last (get-byte pos 65 found-bytes)))]
             (recur (inc pos) (conj found-bytes new-byte)))))))

(defn find-byte [encryption-function attack-bytes]
  (let [attack-ciphertext (into [] (take 16 (encryption-function attack-bytes)))]
    (last (get (letfn [(to-vec [byte-array]
                         (into [] (map identity byte-array)))]
                 (into {} (for [last-byte (range 0 255)]
                            (let [bytes (byte-array (concat attack-bytes (list last-byte)))]
                              {(to-vec (take 16 (map identity (encryption-function bytes))))
                               (to-vec bytes)}))))
               attack-ciphertext))))

(find-byte ecb-oracle first-plaintext-block)
(find-byte ecb-oracle (byte-array (drop 1 (concat first-plaintext-block '(82)))))
(take 32 (map identity (ecb-oracle [])))
(take 16 (ecb-oracle first-plaintext-block))

(find-byte ecb-oracle (drop 1 first-plaintext-block))

(defn decrypt-remainder [first-block]
  (loop [ciphertext (ecb-oracle [])
         attack-bytes first-block
         coll (into [] first-block)]
    (if (empty? ciphertext)
      coll
      (do (println attack-bytes coll)
          (let [new-ciphertext (drop 1 ciphertext)
                new-attack-bytes (concat (drop 1 attack-bytes)
                                         (list (first ciphertext)))
                new-coll (find-byte ecb-oracle attack-bytes)]
            (recur new-ciphertext new-attack-bytes new-coll))))))

(decrypt-remainder first-plaintext-block)

(def first-plaintext-block (get-first-plaintext-block))

(defn get-first-byte []
  (last (get-byte 1 65)))

(take 16 (map identity (ecb-oracle (byte-array (drop 1 (concat first-plaintext-block '(82)))))))

;; TODO rewrite to start with enough padding to hold entire decryption
