(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "Solving Cryptopals problems."
  :url "https://github.com/csdrane/cryptopals"
   :license {:name "MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [commons-codec/commons-codec "1.10"]]
  :plugins []
  :min-lein-version "2.0.0"
  :target-path "target/%s"
  :resource-paths ["resources"]
  :profiles {:uberjar {:aot :all}
             :dev {:plugins [[cider/cider-nrepl "0.8.0-SNAPSHOT"]]}})
