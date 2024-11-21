/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.crypto;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class AsymmetricSignatureSignerContext implements SignatureSignerContext {

    private final KeyWrapper key;

    public AsymmetricSignatureSignerContext(KeyWrapper key) throws SignatureException {
        this.key = key;
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithmOrDefault();
    }

    @Override
    public String getHashAlgorithm() {
        return JavaAlgorithm.getJavaAlgorithmForHash(key.getAlgorithmOrDefault(), key.getCurve());
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(JavaAlgorithm.getJavaAlgorithm(key.getAlgorithmOrDefault(), key.getCurve()));
            signature.initSign((PrivateKey) key.getPrivateKey());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

    @Override
    public String getCertificate() {
        try {
            return Base64.getEncoder().encodeToString(key.getCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            // To-DO: logging?
            return "";
        }
    }

    @Override
    public List<String> getCertificateChain() {
        List<X509Certificate> chain = key.getCertificateChain();
        if (chain == null) {
            return new ArrayList<String>();
        }
        return chain.stream().map(c -> {
            try {
                return Base64.getEncoder().encodeToString(c.getEncoded());
            } catch (CertificateEncodingException e) {
                // To-DO: logging?
                return "";
            }
        }).collect(Collectors.toList());
    }
}
