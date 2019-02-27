package org.jgroups.protocols;

import org.jgroups.JChannel;
import org.jgroups.protocols.pbcast.GMS;
import org.jgroups.protocols.pbcast.NAKACK2;
import org.jgroups.protocols.pbcast.STABLE;
import org.jgroups.stack.Protocol;
import org.jgroups.tests.LeaveTest;
import org.jgroups.util.Util;

import java.util.stream.Stream;

/**
 * Tests graceful leaving of the coordinator and second-in-line in a 10 node cluster with ASYM_ENCRYPT configured.
 * <br/>
 * Reproducer for https://issues.jboss.org/browse/JGRP-2297
 * @author Bela Ban
 * @since  4.0.12
 */
public class ASYM_ENCRYPT_LeaveTest extends LeaveTest {
    protected static final String      KEYSTORE="my-keystore.jks";
    protected static final String      KEYSTORE_PWD="password";
    protected static final int         NUM_LEAVERS=2;

    protected boolean useExternalKeyExchange() {return false;}

    public void testGracefulLeave() throws Exception {
        setup(NUM);
        for(int j=0; j < channels.length; j++)
            System.out.printf("%-4s: view is %s\n", channels[j].getAddress(), channels[j].getView());
        System.out.println("\n");

        JChannel[] remaining_channels=new JChannel[channels.length-NUM_LEAVERS];
        System.arraycopy(channels, NUM_LEAVERS, remaining_channels, 0, channels.length-NUM_LEAVERS);
        Stream.of(channels).map(c -> c.getProtocolStack().findProtocol(GMS.class)).forEach(p -> ((Protocol)p).setLevel("trace"));
        Stream.of(channels).limit(NUM_LEAVERS).forEach(Util::close);
        Util.waitUntilAllChannelsHaveSameView(30000, 1000, remaining_channels);
        for(int i=0; i < remaining_channels.length; i++)
            System.out.printf("%-4s: view is %s\n", remaining_channels[i].getAddress(), remaining_channels[i].getView());
    }




    /** Creates a channel with a config similar to ./conf/asym-ssl.xml */
    @Override protected JChannel create(String name) throws Exception {
        return new JChannel(
          new TCP().setBindAddress(LOOPBACK),
          new MPING(),
          // omit MERGE3 from the stack -- nodes are leaving gracefully
          new SSL_KEY_EXCHANGE().setKeystoreName(KEYSTORE).setKeystorePassword(KEYSTORE_PWD).setPortRange(10),
          new ASYM_ENCRYPT().setUseExternalKeyExchange(useExternalKeyExchange())
            .symKeylength(128).symAlgorithm("AES").asymKeylength(512).asymAlgorithm("RSA"),
          new NAKACK2().setUseMcastXmit(false),
          new UNICAST3(),
          new STABLE(),
          new GMS().joinTimeout(2000).leaveTimeout(10000))
          .name(name);
    }

}
