package canonical;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.erdtman.jcs.JsonCanonicalizer;
import proof.Proof;

import java.io.IOException;


public final class Canonical {
    private static final Gson GSON = new GsonBuilder().registerTypeAdapter(Proof.class, new ProofAdapter()).serializeNulls().create();

    private Canonical() {
    }

    public static String canonicalize(final String json) throws IOException {
        JsonCanonicalizer jsonCanonicalizer = new JsonCanonicalizer(json);
        return jsonCanonicalizer.getEncodedString();
    }

    public static String toJson(final Object o) {
        return GSON.toJson(o);
    }
}

class ProofAdapter extends TypeAdapter<Proof> {
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    @Override
    public void write(JsonWriter out, Proof value) throws IOException {
        out.beginObject();
        if (!value.getCreated().equals("")) {
            out.name("created");
            out.value(value.getCreated());
        }
        if (!value.getNonce().equals("")) {
            out.name("nonce");
            out.value(value.getNonce());
        }
        if (!value.getSignatureValue().equals("")) {
            out.name("signatureValue");
            out.value(value.getSignatureValue());
        }
        if (!value.getVerificationMethod().equals("")) {
            out.name("verificationMethod");
            out.value(value.getVerificationMethod());
        }
        if (!value.getType().equals("")) {
            out.name("type");
            out.value(value.getType());
        }
        out.endObject();
    }

    @Override
    public Proof read(JsonReader in) throws IOException {
        return GSON.fromJson(in.toString(), Proof.class);
    }
}