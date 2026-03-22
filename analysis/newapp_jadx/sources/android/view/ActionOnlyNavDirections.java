package android.view;

import android.os.Bundle;
import androidx.annotation.NonNull;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class ActionOnlyNavDirections implements NavDirections {
    private final int mActionId;

    public ActionOnlyNavDirections(int i2) {
        this.mActionId = i2;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && ActionOnlyNavDirections.class == obj.getClass() && getActionId() == ((ActionOnlyNavDirections) obj).getActionId();
    }

    @Override // android.view.NavDirections
    public int getActionId() {
        return this.mActionId;
    }

    @Override // android.view.NavDirections
    @NonNull
    public Bundle getArguments() {
        return new Bundle();
    }

    public int hashCode() {
        return getActionId() + 31;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ActionOnlyNavDirections(actionId=");
        m586H.append(getActionId());
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }
}
