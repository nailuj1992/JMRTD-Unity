/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: PACEGMWithDHMappingResult.java 1763 2018-02-18 07:41:30Z martijno $
 */

package org.jmrtd.protocol;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * The result of the PACE nonce mapping step in Generic Mapping with Diffie-Hellman setting.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 */
public class PACEGMWithDHMappingResult extends PACEGMMappingResult {

  private static final long serialVersionUID = -2829641255641406199L;

  private byte[] sharedSecret;

  /**
   * Constructs a result.
   *
   * @param staticParameters the static parameters
   * @param piccNonce the nonce that was sent by the PICC
   * @param piccMappingPublicKey the mapping public key sent by the PICC
   * @param pcdMappingKeyPair the key-pair generated by the PCD
   * @param sharedSecret the shared secret that was derived
   * @param ephemeralParameters the ephemeral parameters that were derived
   */
  public PACEGMWithDHMappingResult(AlgorithmParameterSpec staticParameters, byte[] piccNonce,
      PublicKey piccMappingPublicKey, KeyPair pcdMappingKeyPair,
      byte[] sharedSecret, AlgorithmParameterSpec ephemeralParameters) {
    super(staticParameters, piccNonce, piccMappingPublicKey, pcdMappingKeyPair, ephemeralParameters);
    this.sharedSecret = sharedSecret == null ? null : Arrays.copyOf(sharedSecret, sharedSecret.length);
  }

  /**
   * Returns the shared secret that was derived during this protocol step.
   *
   * @return the shared secret
   */
  public byte[] getSharedSecret() {
    return sharedSecret == null ? null : Arrays.copyOf(sharedSecret, sharedSecret.length);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Arrays.hashCode(sharedSecret);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    PACEGMWithDHMappingResult other = (PACEGMWithDHMappingResult) obj;
    return Arrays.equals(sharedSecret, other.sharedSecret);
  }
}
