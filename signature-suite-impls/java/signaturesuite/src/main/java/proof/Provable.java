package proof;

public interface Provable {
    Proof getProof();

    void setProof(Proof proof);

    String toJson();
}