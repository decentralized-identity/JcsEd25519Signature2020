package canonical;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;

public final class Canonical {
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    private Canonical() {}

    public static String canonicalize(final String json) throws IOException {
        JsonCanonicalizer jsonCanonicalizer = new JsonCanonicalizer(json);
        return jsonCanonicalizer.getEncodedString();
    }

    public static String toJson(final Object o) {
        return GSON.toJson(o);
    }
}