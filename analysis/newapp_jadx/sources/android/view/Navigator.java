package android.view;

import android.os.Bundle;
import android.view.NavDestination;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/* loaded from: classes.dex */
public abstract class Navigator<D extends NavDestination> {

    public interface Extras {
    }

    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface Name {
        String value();
    }

    @NonNull
    public abstract D createDestination();

    @Nullable
    public abstract NavDestination navigate(@NonNull D d2, @Nullable Bundle bundle, @Nullable NavOptions navOptions, @Nullable Extras extras);

    public void onRestoreState(@NonNull Bundle bundle) {
    }

    @Nullable
    public Bundle onSaveState() {
        return null;
    }

    public abstract boolean popBackStack();
}
