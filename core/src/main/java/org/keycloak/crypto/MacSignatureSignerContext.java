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

import java.util.List;
import javax.crypto.Mac;
import java.util.ArrayList;

public class MacSignatureSignerContext implements SignatureSignerContext {

    private final KeyWrapper key;

    public MacSignatureSignerContext(KeyWrapper key) throws SignatureException {
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
        return JavaAlgorithm.getJavaAlgorithmForHash(key.getAlgorithmOrDefault());
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Mac mac = Mac.getInstance(JavaAlgorithm.getJavaAlgorithm(key.getAlgorithmOrDefault()));
            mac.init(key.getSecretKey());
            mac.update(data);
            return mac.doFinal();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

    @Override
    public String getCertificate() {
        return null;
    }

    @Override
    public List<String> getCertificateChain() {
        return new ArrayList<String>();
    }
}
