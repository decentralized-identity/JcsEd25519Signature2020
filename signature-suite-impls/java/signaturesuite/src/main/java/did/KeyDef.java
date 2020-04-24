package did;

import canonical.Canonical;

public class KeyDef {
    private final String id;
    private final String type;
    private final String controller;
    private final String publicKeyBase58;

    public KeyDef(final String id, final String type, final String controller, final String publicKeyBase58) {
        this.id = id;
        this.type = type;
        this.controller = controller;
        this.publicKeyBase58 = publicKeyBase58;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getController() {
        return controller;
    }

    public String getPublicKeyBase58() {
        return publicKeyBase58;
    }

    @Override public String toString() {
        return Canonical.toJson(this);
    }
}
