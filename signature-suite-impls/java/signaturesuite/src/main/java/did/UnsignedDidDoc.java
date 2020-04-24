package did;

import canonical.Canonical;

public class UnsignedDidDoc {
    private final String id;
    private final KeyDef[] publicKey;
    private final String[] authentication;
    private final ServiceDef[] service;

    public UnsignedDidDoc(final String id,
                          final KeyDef[] publicKey,
                          final String[] authentication,
                          final ServiceDef[] service) {
        this.id = id;
        this.publicKey = publicKey;
        this.authentication = authentication;
        this.service = service;
    }

    public String getId() {
        return id;
    }

    public KeyDef[] getPublicKey() {
        return publicKey;
    }

    public String[] getAuthentication() {
        return authentication;
    }

    public ServiceDef[] getService() {
        return service;
    }

    @Override public String toString() {
        return Canonical.toJson(this);
    }
}
