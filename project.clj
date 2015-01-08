(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "Solving Cryptopals problems."
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]]
  :plugins []
  :min-lein-version "2.0.0"
  :target-path "target/%s"
  :resource-paths ["resources"]
  :profiles {:uberjar {:aot :all}
             :dev {:plugins [[cider/cider-nrepl "0.8.0-SNAPSHOT"]]}})
