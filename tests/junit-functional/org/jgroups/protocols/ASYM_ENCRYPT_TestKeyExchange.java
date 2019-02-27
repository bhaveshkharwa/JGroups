package org.jgroups.protocols;

import org.testng.annotations.BeforeMethod;

/**
 * Tests use cases for {@link ASYM_ENCRYPT} described in https://issues.jboss.org/browse/JGRP-2021.
 * @author Bela Ban
 * @since  4.0
 */
public class ASYM_ENCRYPT_TestKeyExchange extends ASYM_ENCRYPT_Test {

    @BeforeMethod
    protected void init() throws Exception {
        super.init();
        //Stream.of(a,b,c,d,rogue).filter(Objects::nonNull).map(JChannel::getProtocolStack)
          //.forEach(st -> st.removeProtocol(AUTH.class));
    }

    @Override protected boolean useExternalKeyExchange() {return true;}


    public void testEavesdroppingByLeftMember() throws Exception {
        System.out.println("Skipping this test as the use of an external key exchange will allow left members to " +
                            "decrypt messages received by existing members");
    }

    public void testMessagesByLeftMember() throws Exception {
        System.out.println("Skipping this test as the use of an external key exchange will allow left members to " +
                             "send messages which will be delivered by existing members, as the left member " +
                             "will be able to fetch the secret group key");
    }
}
