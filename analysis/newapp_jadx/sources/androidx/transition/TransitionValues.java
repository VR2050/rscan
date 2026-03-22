package androidx.transition;

import android.view.View;
import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class TransitionValues {
    public View view;
    public final Map<String, Object> values = new HashMap();
    public final ArrayList<Transition> mTargetedTransitions = new ArrayList<>();

    @Deprecated
    public TransitionValues() {
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof TransitionValues)) {
            return false;
        }
        TransitionValues transitionValues = (TransitionValues) obj;
        return this.view == transitionValues.view && this.values.equals(transitionValues.values);
    }

    public int hashCode() {
        return this.values.hashCode() + (this.view.hashCode() * 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("TransitionValues@");
        m586H.append(Integer.toHexString(hashCode()));
        m586H.append(":\n");
        StringBuilder m590L = C1499a.m590L(m586H.toString(), "    view = ");
        m590L.append(this.view);
        m590L.append("\n");
        String m637w = C1499a.m637w(m590L.toString(), "    values:");
        for (String str : this.values.keySet()) {
            m637w = m637w + "    " + str + ": " + this.values.get(str) + "\n";
        }
        return m637w;
    }

    public TransitionValues(@NonNull View view) {
        this.view = view;
    }
}
