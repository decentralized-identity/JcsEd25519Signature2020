package did;

import canonical.Canonical;

public class ServiceDef {
    private final String id;
    private final String type;
    private final String serviceEndpoint;

    public ServiceDef(final String id, final String type, final String serviceEndpoint) {
        this.id = id;
        this.type = type;
        this.serviceEndpoint = serviceEndpoint;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getServiceEndpoint() {
        return serviceEndpoint;
    }

    @Override public String toString() {
        return Canonical.toJson(this);
    }
}
