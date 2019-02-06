package org.jgroups.protocols;

import org.jgroups.Address;
import org.jgroups.Event;
import org.jgroups.Message;
import org.jgroups.View;
import org.jgroups.annotations.MBean;
import org.jgroups.annotations.ManagedAttribute;
import org.jgroups.annotations.Property;
import org.jgroups.conf.ClassConfigurator;
import org.jgroups.protocols.pbcast.GMS;
import org.jgroups.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;

/**
 * Encrypts and decrypts communication in JGroups by using a secret key distributed to all cluster members by the
 * key server (coordinator) using asymmetric (public/private key) encryption.<br>
 *
 * The secret key is identical for all cluster members and is used to encrypt messages when sending and decrypt them
 * when receiving messages.
 *
 * This protocol is typically placed under {@link org.jgroups.protocols.pbcast.NAKACK2}.<br>
 *
 * The current keyserver (always the coordinator) generates a secret key. When a new member joins, it asks the keyserver
 * for the secret key. The keyserver encrypts the secret key with the joiner's public key and the joiner decrypts it with
 * its private key and then installs it and starts encrypting and decrypting messages with the secret key.<br>
 *
 * View changes that identify a new keyserver will result in a new secret key being generated and then distributed to
 * all cluster members. This overhead can be substantial in an application with a reasonable member churn.<br>
 *
 * This protocol is suited for an application that does not ship with a known key but instead it is generated and
 * distributed by the keyserver.
 *
 * Since messages can only get encrypted and decrypted when the secret key was received from the keyserver, messages
 * are dropped when the secret key hasn't been installed yet.
 *
 * @author Bela Ban
 * @author Steve Woodcock
 */
@MBean(description="Asymmetric encryption protocol. The secret key for encryption and decryption of messages is fetched " +
  "from a key server (the coordinator) via asymmetric encryption")
public class ASYM_ENCRYPT extends Encrypt<KeyStore.PrivateKeyEntry> {
    protected static final short                   GMS_ID=ClassConfigurator.getProtocolId(GMS.class);

    @Property(description="When a member leaves, change the secret key, preventing old members from eavesdropping")
    protected boolean                              change_key_on_leave=true;

    @Property(description="If true, a separate KeyExchange protocol (somewhere below in ths stack) is used to" +
      " fetch the shared secret key. If false, the default (built-in) key exchange protocol will be used.")
    protected boolean                              use_external_key_exchange;

    protected volatile Address                     key_server_addr;
    protected KeyPair                              key_pair;     // to store own's public/private Key
    protected Cipher                               asym_cipher;  // decrypting cypher for secret key requests

    // use registerBypasser to add code that is called to check if a message should bypass ASYM_ENCRYPT
    protected List<BiPredicate<Message,Boolean>>   bypassers;

    // map of members and their public keys
    protected final Map<Address,byte[]>            pub_map=new ConcurrentHashMap<>();



    @Override
    public void setKeyStoreEntry(KeyStore.PrivateKeyEntry entry) {
        this.key_pair = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
    }

    public boolean      getChangeKeyOnLeave()                {return change_key_on_leave;}
    public ASYM_ENCRYPT setChangeKeyOnLeave(boolean c)       {change_key_on_leave=c; return this;}

    public boolean      getUseExternalKeyExchange()          {return use_external_key_exchange;}
    public ASYM_ENCRYPT setUseExternalKeyExchange(boolean u) {use_external_key_exchange=u; return this;}

    public KeyPair      keyPair()                            {return key_pair;}
    public Cipher       asymCipher()                         {return asym_cipher;}
    public Address      keyServerAddr()                      {return key_server_addr;}
    public ASYM_ENCRYPT keyServerAddr(Address ks)            {this.key_server_addr=ks; return this;}

    public List<Integer> providedDownServices() {
        return Arrays.asList(Event.GET_SECRET_KEY, Event.SET_SECRET_KEY);
    }

    public synchronized ASYM_ENCRYPT registerBypasser(BiPredicate<Message,Boolean> bypasser) {
        if(bypasser != null) {
            if(bypassers == null)
                bypassers=new ArrayList<>();
            bypassers.add(bypasser);
        }
        return this;
    }

    public synchronized ASYM_ENCRYPT unregisterBypasser(BiPredicate<Message,Boolean> bypasser) {
        if(bypasser != null && bypassers != null) {
            if(bypassers.remove(bypasser) && bypassers.isEmpty())
                bypassers=null;
        }
        return this;
    }

    @ManagedAttribute(description="Keys in the public key map")
    public String getPublicKeys() {
        return pub_map.keySet().toString();
    }

    @ManagedAttribute(description="The current key server")
    public String getKeyServerAddress() {return key_server_addr != null? key_server_addr.toString() : "null";}


    @ManagedAttribute(description="True if this member is the current key server, false otherwise")
    public boolean isKeyServer() {
        return Objects.equals(key_server_addr, local_addr);
    }

    public void init() throws Exception {
        initKeyPair();
        super.init();
        if(use_external_key_exchange) {
            List<Integer> provided_up_services=getDownServices();
            if(provided_up_services == null || !provided_up_services.contains(Event.FETCH_SECRET_KEY))
                throw new IllegalStateException("found no key exchange protocol below servicing event FETCH_SECRET_KEY");
        }
    }


    public void start() throws Exception {
        super.start();
        pub_map.put(local_addr, key_pair.getPublic().getEncoded());
    }

    public Object down(Message msg) {
        Processing processing=skipDownMessage(msg);
        if(processing == Processing.PROCESS)
            return super.down(msg);
        if(processing == Processing.SKIP || bypass(msg, false))
            return down_prot.down(msg);
        return null; // DROP
    }

    public Object up(Event evt) {
        switch(evt.type()) {
            case Event.GET_SECRET_KEY:
                return new Tuple<>(secret_key, sym_version);
            case Event.SET_SECRET_KEY:
                Tuple<SecretKey,byte[]> tuple=evt.arg();
                try {
                    installSharedGroupKey(null, tuple.getVal1(), tuple.getVal2());
                }
                catch(Exception ex) {
                    log.error("failed setting group key", ex);
                }
                return null;
        }
        return up_prot.up(evt);
    }

    public Object up(Message msg) {
        if(skipUpMessage(msg) || bypass(msg, true))
            return up_prot.up(msg);
        return super.up(msg);
    }

    public void up(MessageBatch batch) {
        for(Message msg: batch) {
            if(skipUpMessage(msg) || bypass(msg, true)) {
                try {
                    up_prot.up(msg);
                    batch.remove(msg);
                }
                catch(Throwable t) {
                    log.error("failed passing up message from %s: %s, ex=%s", msg.src(), msg.printHeaders(), t);
                }
                continue;
            }
            EncryptHeader eh=msg.getHeader(this.id);
            if(eh != null && eh.type != EncryptHeader.ENCRYPT) {
                handleUpEvent(msg, eh);
                batch.remove(msg);
            }
        }
        if(!batch.isEmpty())
            super.up(batch); // decrypt the rest of the messages in the batch (if any)
    }


    @Override protected Object handleUpEvent(Message msg, EncryptHeader hdr) {
        switch(hdr.type()) {
            case EncryptHeader.PUB_KEY:
                installPublicKeys(msg.getSrc(), msg.getRawBuffer(), msg.getOffset(), msg.getLength());
                break;
            case EncryptHeader.INSTALL_SHARED_KEY:
                handleSharedGroupKeyResponse(msg.getSrc(), hdr.version(), msg.getRawBuffer(), msg.getOffset(), msg.getLength());
                break;
            case EncryptHeader.FETCH_SHARED_KEY:
                down_prot.down(new Event(Event.FETCH_SECRET_KEY, msg.getSrc()));
                break;
        }
        return null;
    }

    /**
     * Processes a message with a GMS header (e.g. by adding the secret key to a JOIN response) and returns true if
     * the message should be passed down (not encrypted) or false if the message needs to be encrypted
     * @return Processing {@link Processing#DROP} if the message needs to be dropped, {@link Processing#SKIP} if the
     *           message needs to be skipped (not encrypted), or {@link Processing#PROCESS} if the message needs to be
     *           processed (= encrypted)
     */
    protected Processing skipDownMessage(Message msg) {
        GMS.GmsHeader hdr=msg.getHeader(GMS_ID);
        if(hdr == null)
            return Processing.PROCESS;
        switch(hdr.getType()) {
            case GMS.GmsHeader.JOIN_REQ:
            case GMS.GmsHeader.JOIN_REQ_WITH_STATE_TRANSFER:
                if(!use_external_key_exchange) {
                    // attach our public key to the JOIN-REQ
                    EncryptHeader h=new EncryptHeader(EncryptHeader.PUB_KEY, symVersion())
                      .key(key_pair.getPublic().getEncoded());
                    msg.putHeader(this.id, h);
                }
                return Processing.SKIP;
            case GMS.GmsHeader.JOIN_RSP:
                if(use_external_key_exchange) {
                    // send a FETCH_SHARED_KEY unicast to the joiner; this causes the joiner to fetch and install the
                    // shared key *before* delivering the JOIN_RSP (so it can decrypt it)
                    log.trace("%s: asking %s to fetch the shared group key %s via an external key exchange protocol",
                              local_addr, msg.getDest(), Util.byteArrayToHexString(sym_version));
                    down_prot.down(new Message(msg.getDest())
                                     .putHeader(id, new EncryptHeader(EncryptHeader.FETCH_SHARED_KEY, symVersion())));
                    break;
                }
                // add the shared group key, encrypted with the destination's public key (should be in pub_map)
                byte[] pk=pub_map.get(msg.getDest());
                if(pk == null) {
                    log.error("%s: public key (to encrypted shared group key) for %s not found in pub-map",
                              local_addr, msg.dest());
                    break;
                }
                try {
                    Message encrypted_msg=encrypt(msg);
                    byte[] encryptedKey=encryptSecretKey(secret_key, makePublicKey(pk));
                    EncryptHeader eh=encrypted_msg.getHeader(id);
                    eh.key(encryptedKey);
                    log.debug("%s: sending encrypted group key to %s (version: %s)",
                              local_addr, encrypted_msg.getDest(), Util.byteArrayToHexString(sym_version));
                    down_prot.down(encrypted_msg);
                    sendPublicKeys(msg.getDest()); // send a PUB_KEY message to the joiner
                    return Processing.DROP; // the encrypted msg was already sent; no need to send the un-encrypted msg
                }
                catch(Exception e) {
                    log.warn("%s: unable to send message down: %s", local_addr, e);
                    return Processing.PROCESS;
                }
            case GMS.GmsHeader.MERGE_REQ:
            case GMS.GmsHeader.MERGE_RSP:
            case GMS.GmsHeader.VIEW_ACK:
            case GMS.GmsHeader.GET_DIGEST_REQ:
            case GMS.GmsHeader.GET_DIGEST_RSP:
                return Processing.SKIP;
        }
        return Processing.PROCESS;
    }

    /** Checks if the message contains a public key (and adds it to pub_map if present) or an encrypted group key
     * (and installs it if present) */
    protected boolean skipUpMessage(Message msg) {
        GMS.GmsHeader hdr=msg.getHeader(GMS_ID);
        if(hdr == null)
            return false;

        EncryptHeader h=msg.getHeader(id);
        switch(hdr.getType()) {
            case GMS.GmsHeader.JOIN_REQ:
            case GMS.GmsHeader.JOIN_REQ_WITH_STATE_TRANSFER: // get the public key from the JOIN-REQ
                if(h != null && h.key() != null) {
                    pub_map.put(msg.src(), h.key());
                    sendPublicKeys(null); // multicast PUB_KEY message to other members (*exclude self*!)
                }
                return true;
            case GMS.GmsHeader.JOIN_RSP:
                if(h != null && h.key() != null)
                    handleSharedGroupKeyResponse(msg.getSrc(), h.version(), h.key());
                break;
            case GMS.GmsHeader.MERGE_REQ:
            case GMS.GmsHeader.MERGE_RSP:
            case GMS.GmsHeader.VIEW_ACK:
            case GMS.GmsHeader.GET_DIGEST_REQ:
            case GMS.GmsHeader.GET_DIGEST_RSP:
                return true;
        }
        return false;
    }

    protected boolean bypass(Message msg, boolean up) {
        List<BiPredicate<Message,Boolean>> tmp=bypassers;
        if(tmp == null)
            return false;
        for(BiPredicate<Message,Boolean> pred: tmp) {
            if(pred.test(msg, up))
                return true;
        }
        return false;
    }


    protected void handleSharedGroupKeyResponse(Address sender, byte[] key_version, byte[] encrypted_key) {
        if(!inView(sender, "ignoring group key sent by %s which is not in current view %s"))
            return;

        if(Arrays.equals(sym_version, key_version)) {
            log.debug("%s: group key (version %s) already installed, ignoring group key received from %s",
                      local_addr, Util.byteArrayToHexString(key_version), sender);
            return;
        }
        try {
            SecretKey tmp=decodeKey(encrypted_key);
            if(tmp != null)
                installSharedGroupKey(sender, tmp, key_version); // otherwise set the received key as the shared key
        }
        catch(Exception e) {
            log.warn("%s: unable to decode encrypted group key received from %s: %s", local_addr, sender, e);
        }
    }

    protected void installPublicKeys(Address sender, byte[] buf, int offset, int length) {
        ByteArrayDataInputStream in=new ByteArrayDataInputStream(buf, offset, length);
        try {
            int num_keys=in.readInt();
            for(int i=0; i < num_keys; i++) {
                Address mbr=Util.readAddress(in);
                int len=in.readInt();
                byte[] key=new byte[len];
                in.readFully(key, 0, key.length);
                pub_map.put(mbr, key);
            }
            log.trace("%s: added %d public keys to local cache", local_addr, num_keys);
        }
        catch(Exception ex) {
            log.error("%s: failed reading public keys received from %s: %s", local_addr, sender, ex);
        }
    }

    protected void sendPublicKeys(Address dest) {
        try {
            Buffer serialized_keys=serializeKeys(pub_map);
            if(serialized_keys == null)
                return;
            log.trace("%s: sending %d public keys to %s", local_addr, pub_map.size(), dest == null? "all members" : dest);
            Message msg=new Message(dest, serialized_keys).setTransientFlag(Message.TransientFlag.DONT_LOOPBACK)
              .putHeader(id, new EncryptHeader(EncryptHeader.PUB_KEY, symVersion()));
            down_prot.down(msg);
        }
        catch(Exception ex) {
            log.error("%s: failed writing pub-key map to message: %s", local_addr, ex);
        }
    }

    /** Encrypt the shared group key with the public key of each member and send the encrypted keys as body of a msg */
    protected void sendSharedGroupKeys(Address dest) {
        try {
            Map<Address,byte[]> encrypted_shared_keys=new HashMap<>(pub_map.size());
            for(Map.Entry<Address,byte[]> e: pub_map.entrySet()) {
                Address mbr=e.getKey();
                byte[] encoded_pk=e.getValue();
                PublicKey pk=makePublicKey(encoded_pk);
                byte[] encrypted_shared_key=encryptSecretKey(secret_key, pk);
                encrypted_shared_keys.put(mbr, encrypted_shared_key);
            }
            Buffer serialized_keys=serializeKeys(encrypted_shared_keys);
            if(serialized_keys == null)
                return;
            log.trace("%s: sending %d encrypted shared group key(s) to %s (version: %s)",
                      local_addr, pub_map.size(), dest == null? "all members" : dest, Util.byteArrayToHexString(sym_version));
            Message msg=new Message(dest, serialized_keys).setTransientFlag(Message.TransientFlag.DONT_LOOPBACK)
              .putHeader(id, new EncryptHeader(EncryptHeader.INSTALL_SHARED_KEY, symVersion()));
            down_prot.down(msg);
        }
        catch(Exception ex) {
            log.error("%s: failed writing shared group keys to message: %s", local_addr, ex);
        }
    }

    /** Reads the encrypted shared group keys from the buffer, then picks the one for this member, decrypts
     * it with the public key and installs it */
    protected void handleSharedGroupKeyResponse(Address sender, byte[] version, byte[] buf, int offset, int length) {
        if(!inView(sender, "ignoring shared group key sent by %s which is not in current view %s"))
            return;

        if(Arrays.equals(sym_version, version)) {
            log.debug("%s: group key (version %s) already installed, ignoring key response from %s",
                      local_addr, Util.byteArrayToHexString(version), sender);
            return;
        }
        Map<Address,byte[]> shared_keys=unserializeKeys(sender, buf, offset, length);
        byte[] encrypted_key=shared_keys != null? shared_keys.get(local_addr) : null;
        if(encrypted_key == null) {
            log.warn("%s: found no encrypted shared group key for me in map, cannot install new group key", local_addr);
            return;
        }
        try {
            SecretKey tmp=decodeKey(encrypted_key);
            if(tmp != null)
                installSharedGroupKey(sender, tmp, version); // otherwise set the received key as the shared key
        }
        catch(Exception e) {
            log.warn("%s: unable to process key received from %s: %s", local_addr, sender, e);
        }
    }

    protected static Buffer serializeKeys(Map<Address,byte[]> keys) throws Exception {
        int num_keys=keys.size();
        if(num_keys == 0)
            return null;
        ByteArrayDataOutputStream out=new ByteArrayDataOutputStream(num_keys * 100);
        out.writeInt(num_keys);
        for(Map.Entry<Address,byte[]> e: keys.entrySet()) {
            Util.writeAddress(e.getKey(), out);
            byte[] val=e.getValue();
            out.writeInt(val.length);
            out.write(val, 0, val.length);
        }
        return out.getBuffer();
    }

    protected Map<Address,byte[]> unserializeKeys(Address sender, byte[] buf, int offset, int length) {
        Map<Address,byte[]> map=new HashMap<>();
        ByteArrayDataInputStream in=new ByteArrayDataInputStream(buf, offset, length);
        try {
            int num_keys=in.readInt();
            for(int i=0; i < num_keys; i++) {
                Address mbr=Util.readAddress(in);
                int len=in.readInt();
                byte[] key=new byte[len];
                in.readFully(key, 0, key.length);
                map.put(mbr, key);
            }
        }
        catch(Exception ex) {
            log.error("%s: failed reading keys received from %s: %s", local_addr, sender, ex);
        }
        return map;
    }


    /** Initialise the symmetric key if none is supplied in a keystore */
    protected SecretKey createSecretKey() throws Exception {
        KeyGenerator keyGen=null;
        // see if we have a provider specified
        if(provider != null && !provider.trim().isEmpty())
            keyGen=KeyGenerator.getInstance(getAlgorithm(sym_algorithm), provider);
        else
            keyGen=KeyGenerator.getInstance(getAlgorithm(sym_algorithm));
        // generate the key using the defined init properties
        keyGen.init(sym_keylength);
        return keyGen.generateKey();
    }



    /** Generates the public/private key pair from the init params */
    protected void initKeyPair() throws Exception {
        if (this.key_pair == null) {
            // generate keys according to the specified algorithms
            // generate publicKey and Private Key
            KeyPairGenerator KpairGen=null;
            if(provider != null && !provider.trim().isEmpty())
                KpairGen=KeyPairGenerator.getInstance(getAlgorithm(asym_algorithm), provider);
            else
                KpairGen=KeyPairGenerator.getInstance(getAlgorithm(asym_algorithm));
            KpairGen.initialize(asym_keylength,new SecureRandom());
            key_pair=KpairGen.generateKeyPair();
        }

        // set up the Cipher to decrypt secret key responses encrypted with our key
        if(provider != null && !provider.trim().isEmpty())
            asym_cipher=Cipher.getInstance(asym_algorithm, provider);
        else
            asym_cipher=Cipher.getInstance(asym_algorithm);
        asym_cipher.init(Cipher.DECRYPT_MODE, key_pair.getPrivate());
    }


    @Override protected void handleView(View v) {
        boolean left_mbrs, create_new_key;
        Address old_key_server;

        pub_map.keySet().retainAll(v.getMembers());

        synchronized(this) {
            left_mbrs=change_key_on_leave && this.view != null && !v.containsMembers(this.view.getMembersRaw());
            create_new_key=secret_key == null || left_mbrs;
            super.handleView(v);
            old_key_server=key_server_addr;
            key_server_addr=v.getCoord(); // the coordinator is the keyserver
            if(Objects.equals(key_server_addr, local_addr)) {
                if(!Objects.equals(key_server_addr, old_key_server))
                    log.debug("%s: I'm the new key server", local_addr);
                if(create_new_key) {
                    createNewKey();
                    if(!left_mbrs)
                        return;
                    if(use_external_key_exchange) {
                        // multicast a FETCH_SHARED_KEY unicast to all members; this causes the members to fetch and
                        // install the new shared key *before* delivering the VIEW (so they can decrypt it)
                        log.trace("%s: asking all members to fetch the shared key %s via an external key exchange protocol",
                                  local_addr, Util.byteArrayToHexString(sym_version));
                        down_prot.down(new Message(null).setTransientFlag(Message.TransientFlag.DONT_LOOPBACK)
                                         .putHeader(id, new EncryptHeader(EncryptHeader.FETCH_SHARED_KEY, symVersion())));
                    }
                    else // multicast an INSTALL_SHARED_KEY message to all members (delivered before the view message)
                        sendSharedGroupKeys(null);
                }
            }
        }
    }


    protected void createNewKey() {
        try {
            this.secret_key=createSecretKey();
            initSymCiphers(sym_algorithm, secret_key);
            log.debug("%s: created new group key (version: %s)", local_addr, Util.byteArrayToHexString(sym_version));
            cacheGroupKey(sym_version);
        }
        catch(Exception ex) {
            log.error("%s: failed creating group key and initializing ciphers", local_addr, ex);
        }
    }


    protected synchronized void installSharedGroupKey(Address sender, SecretKey key, byte[] version) throws Exception {
        if(Arrays.equals(this.sym_version, version)) {
            log.debug("%s: ignoring group key received from %s (version: %s); it has already been installed",
                      local_addr, sender != null? sender : "key exchange protocol", Util.byteArrayToHexString(version));
            return;
        }
        log.debug("%s: installing group key received from %s (version: %s)",
                  local_addr, sender != null? sender : "key exchange protocol", Util.byteArrayToHexString(version));
        secret_key=key;
        initSymCiphers(key.getAlgorithm(), key);
        sym_version=version;
        cacheGroupKey(version);
    }

    /** Cache the current shared key (and its cipher) to decrypt messages encrypted with the old shared group key */
    protected void cacheGroupKey(byte[] version) throws Exception {
        Cipher decoding_cipher=secret_key != null? decoding_ciphers.take() : null;
        // put the previous key into the map, keep the cipher: no leak, as we'll recreate decoding_ciphers in initSymCiphers()
        if(decoding_cipher != null)
            key_map.putIfAbsent(new AsciiString(version), decoding_cipher);
    }

    /** Encrypts the current secret key with the requester's public key (the requester will decrypt it with its private key) */
    protected byte[] encryptSecretKey(Key secret_key, PublicKey public_key) throws Exception {
        Cipher tmp;
        if (provider != null && !provider.trim().isEmpty())
            tmp=Cipher.getInstance(asym_algorithm, provider);
        else
            tmp=Cipher.getInstance(asym_algorithm);
        tmp.init(Cipher.ENCRYPT_MODE, public_key);

        // encrypt current secret key
        return tmp.doFinal(secret_key.getEncoded());
    }


    protected SecretKeySpec decodeKey(byte[] encodedKey) throws Exception {
        byte[] keyBytes;

        synchronized(this) {
            try {
                keyBytes=asym_cipher.doFinal(encodedKey);
            }
            catch (BadPaddingException | IllegalBlockSizeException e) {
                //  if any exception is thrown, this cipher object may need to be reset before it can be used again.
                asym_cipher.init(Cipher.DECRYPT_MODE, key_pair.getPrivate());
                throw e;
            }
        }

        try {
            SecretKeySpec keySpec=new SecretKeySpec(keyBytes, getAlgorithm(sym_algorithm));
            Cipher temp;
            if (provider != null && !provider.trim().isEmpty())
                temp=Cipher.getInstance(sym_algorithm, provider);
            else
                temp=Cipher.getInstance(sym_algorithm);
            temp.init(Cipher.SECRET_KEY, keySpec);
            return keySpec;
        }
        catch(Exception e) {
            log.error(Util.getMessage("FailedDecodingKey"), e);
            return null;
        }
    }

    /** Used to reconstitute public key sent in byte form from peer */
    protected PublicKey makePublicKey(byte[] encodedKey) {
        PublicKey pubKey=null;
        try {
            KeyFactory KeyFac=KeyFactory.getInstance(getAlgorithm(asym_algorithm));
            X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(encodedKey);
            pubKey=KeyFac.generatePublic(x509KeySpec);
        }
        catch(Exception e) {
            e.printStackTrace();
        }
        return pubKey;
    }

    protected enum Processing {SKIP, PROCESS, DROP}
}
