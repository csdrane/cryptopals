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
(def ic-text "QPWKALVRXCQZIKGRBPFAEOMFLJMSDZVDHXCXJYEBIMTRQWNMEAIZRVKCVKVLXNEICFZPZCZZHKMLVZVZIZRRQWDKECHOSNYXXLSPMYKVQXJTDCIOMEEXDQVSRXLRLKZHOV")

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

;; data from http://en.wikipedia.org/wiki/Index_of_coincidence
(deftest ic
  (is (> 0.10 (- 1.82 (apply cp/avg (map cp/ic (cp/transpose-data (cp/get-chunks ic-text 5)))))))
  (is (> 0.10 (- 1.03 (cp/ic (apply str (map char (map cp/xor (repeat 53) (cp/parse-hex-string "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")))))))))

;; Observe: index of coincidence is unable to solve problem 1.4; solved initially using word counting. See test `decode-xor-string`.
(deftest ic-fails-to-solve-1-4
  (is (not= (get (cp/ic-cols
                       (cp/parse-hex-string
                        "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")
                       (range 2 100)) :key) 53)))

;;;;;;;; Scratchpad

;; (sort-by :norm-score <
;;          (for [x (range 2 100)]
;;            (let [text (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) x))
;;                  ic (cp/ic text)
;;                  m {:key x :score ic :norm-score (Math/abs (- ic 1.75))}]
;;              m)))

(def aggregate-ic (apply cp/avg (map :ic (map #(cp/ic-cols % (range 32 128)) (cp/transpose-data (cp/get-chunks prob-6-data 29))))))

(def decrypt-key (apply str
        (map (comp char :key)
             ((fn [data keys]
                (map #(cp/ic-cols % keys) data))
              (cp/transpose-data (cp/get-chunks prob-6-data 29)) (range 32 128)))))

(defn decrypt-with-key [text decrypt-key]
  (loop [text text
         key decrypt-key
         coll ""]
    (if (empty? text)
      coll
      (recur (rest text) (take (count key) (drop 1 (cycle key)))
             (str coll (char (cp/xor (first text) (int (first key)))))))))

(defn score-letters1 [text]
  "First attempt at scoring text using letter frequency. Adds 1 for each occurence of 5 most common letters."
  (let [lower-case-text (str/lower-case text)
        score (reduce (fn [i c]
                        (if (re-matches #"[a-z]" (str c))
                          (inc i)
                          (- i 1))) 0 lower-case-text)]
    score))

(def transposed-data (cp/transpose-data (cp/get-chunks prob-6-data 29)))

(def decrypt-key (apply str
        (map
         (comp char
               :key
               (fn [cipher-text]
                 (first
                  (sort-by :score >
                           (for [x (range 32 128)]
                             (let [text (map char (cp/xor-array cipher-text x))
                                   score (score-letters1 text)
                                   m {:key x :score score}]
                               m))))))
         transposed-data)))

; "PcCY**^,9T!ia  #US,)[)'&g)2=!"

(apply str (map (comp char cp/xor) (first transposed-data) (repeat (int \c))))

; next up, try implementing english_probability from https://github.com/mmueller/cryptopals/blob/master/textutil.py

~~~~

(def english-frequency
  { \E 0.1202
    \T 0.0910
    \A 0.0812
    \O 0.0768
    \I 0.0731
    \N 0.0695
    \S 0.0628
    \R 0.0602
    \H 0.0592
    \D 0.0432
    \L 0.0398
    \U 0.0288
    \C 0.0271
    \M 0.0261
    \F 0.0230
    \Y 0.0211
    \W 0.0209
    \G 0.0203
    \P 0.0182
    \B 0.0149
    \V 0.0111
    \K 0.0069
    \X 0.0017
    \Q 0.0011
    \J 0.0010
    \Z 0.0007}
  )

(defn english-probability [text]
  (let [text (str/upper-case text)
        letters (into #{} (keys english-frequency))
        text-letters (filter letters text)
        non-letters (filter #(not (letters %)) text)
        spaces (filter #(= % \space) non-letters)
        non-spaces (filter #(not= % \space) non-letters)
        space-error (Math/abs (- (float (/ (count spaces)
                                           (count text)))
                                 0.15))
        punc-error (Math/abs (- (float (/ (count non-spaces)
                                          (count text)))
                                0.02))
        letter-error (reduce (fn [i [letter frequency]]
                               (+ i (* frequency
                                       (Math/abs (- 
                                                  (/ (count (filter #{letter} letters))
                                                     (count text-letters))
                                                  frequency))))) 0.0 english-frequency)]
    (max (- 1 (+ punc-error space-error letter-error)) 0.0))) 

(defn get-decryption-key [scoring-method transposed-data]
  (apply str
         (map
          (comp char
                :key
                (fn [cipher-text]
                  (first
                   (sort-by :score >
                            (for [x (range 32 128)]
                              (let [text (apply str (map char (cp/xor-array cipher-text x)))
                                    score (scoring-method text)
                                    m {:key x :score score}]
                                m))))))
          transposed-data)))

(get-decryption-key english-probability (cp/transpose-data (cp/get-chunks prob-6-data 29)))

(map (fn [cipher-text]
       (first (sort-by :score >
                       (for [x (range 32 128)]
                         (let [text (map char (cp/xor-array cipher-text x))
                               score (english-probability text)
                               m {:key (char x) :score score}]
                           m)))))
     (cp/transpose-data (cp/get-chunks prob-6-data 29)))

(map char (cp/xor-array (cp/xor-array (.getBytes (String. "This is not my string.")) 53) 53))

(english-probability "this is a test.")

(for [x (range 32 128)]
  (let [dec (apply str (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) x)))]
    (println "Key" x (char x) "-" "Score" (english-probability dec) "-" dec )))

(for [x (range 32 128)]
  (let [text (apply str (map char (cp/xor-array  (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) x)))
        score (english-probability text)
        m {:key x :score score}]
    m))

(english-probability (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) 80)))

;; (\g \` \p \f \ \k \m \} \$ \k \} \e \e \v \a \p \j \e \k \a \q \#
;; \j \$ \$ \g \f \$ \a \$ \k \ \` \l \ \$ \v \e \k \} \a \c \} \$
;; \b \a \$ \e \e \| \k \* \k \f \l \$ \] \q \a \$ \$ \# \j \e \$ \j
;; \c \l \` \5 \p \t \$ \k \j \e \r \e \m \k \i \i \a \g \j \ \$ \k
;; \v \$ \e \j \$ \h \g \l \f \M)
;; score 0.6654055671468861

(english-probability (apply str (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) 80))))

;; "g`pfkm}$k}eevapjekaq#j$$gf$a$k`l$vek}ac}$ba$ee|k*kfl$]qa$$#je$jcl`5pt$kjeremkiiagj$kv$ej$hglfM"
;; score 0.4835792553707592

(english-probability (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) 84)))

;; (\c \d \t \b \newline \o \i \y \space \o \y \a \a \r \e \t \n \a \o
;; \e \u \' \n \space \space \c \b \space \e \space \o \newline \d \h
;; \newline \space \r \a \o \y \e \g \y \space \f \e \space \a \a \x
;; \o \. \o \b \h \space \Y \u \e \space \space \' \n \a \space \n \g
;; \h \d \1 \t \p \space \o \n \a \v \a \i \o \m \m \e \c \n \newline
;; \space \o \r \space \a \n \space \l \c \h \b \I)
;; score 0.4640317814218563

(english-probability (apply str (map char (cp/xor-array (first (cp/transpose-data (cp/get-chunks prob-6-data 29))) 84))))

;; "cdtb\noiy oyaaretnaoeu'n  cb e o\ndh\n raoyegy fe aaxo.obh Yue  'na nghd1tp onavaiommecn\n or an lchbI"
;; 0.8736437098881186
