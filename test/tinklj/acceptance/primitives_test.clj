(ns tinklj.acceptance.primitives-test
  (:require [clojure.test :refer [deftest testing is]]
            [tinklj.config.tink-config :refer [register]]
            [tinklj.keys.keyset-handle :as keyset-handle]
            [tinklj.primitives :as sut])
  (:import (com.google.crypto.tink.aead AeadFactory)
           (com.google.crypto.tink.mac MacFactory)
           (com.google.crypto.tink.streamingaead StreamingAeadHelper)
           (com.google.crypto.tink.daead DeterministicAeadFactory)
           (com.google.crypto.tink.signature PublicKeySignFactory
                                             PublicKeyVerifyFactory)
           (com.google.crypto.tink.hybrid HybridDecryptFactory
                                          HybridEncryptFactory)
           (java.security GeneralSecurityException
                          InvalidKeyException)))

(deftest aead-primitive-test
  (register)
  (testing "Aead Primitive with correct keyset handle"

    (is (instance? com.google.crypto.tink.aead.AeadFactory$1
                   (sut/aead (keyset-handle/generate-new :aes128-gcm)))))

  (testing "Aead Primitive with incorrect keyset handle"

    (is (thrown? java.security.GeneralSecurityException
                 (sut/aead (keyset-handle/generate-new :ecdsa-p256))))))

(deftest mac-primitive-test
  (register)
  (testing "Mac primitive with correct keyset handle"

    (is (instance? com.google.crypto.tink.mac.MacFactory$1
                   (sut/mac (keyset-handle/generate-new :hmac-sha256-128bittag)))))

  (testing "Mac primitive with incorrect keyset handle"

    (is (thrown? java.security.GeneralSecurityException
                (sut/mac (keyset-handle/generate-new :ecdsa-p384))))))

(deftest streaming-primitive-test
  (register)
  (testing "Streaming primitive with correct keyset handle"

    (is (instance? com.google.crypto.tink.streamingaead.StreamingAeadHelper
                   (sut/streaming (keyset-handle/generate-new :aes128-gcm-hkdf-4kb)))))

  (testing "Streaming primitive with incorrect keyset handle"

    (is (thrown? java.security.GeneralSecurityException
                (sut/streaming (keyset-handle/generate-new :ecdsa-p384))))))

(deftest deterministic-primitive-test
  (register)
  (testing "Streaming primitive with correct keyset handle"

    (is (instance? com.google.crypto.tink.streamingaead.StreamingAeadHelper
                   (sut/deterministic (keyset-handle/generate-new :aes256-siv)))))

  (testing "Streaming primitive with incorrect keyset handle"

    (is (thrown? java.security.GeneralSecurityException
                 (sut/deterministic (keyset-handle/generate-new :ecdsa-p384))))))
