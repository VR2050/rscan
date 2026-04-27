package org.webrtc.mozi;

import android.app.Activity;
import android.content.Context;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class WindowRotationContextHelper {

    @Nullable
    private static WindowContext windowContext;

    @Nullable
    private static IContextProvider windowHostActivityProvider;

    public interface IContextProvider {
        @Nullable
        Context getWindowHostActivityContext();
    }

    public interface WindowContext {
        void addWindowRotationLister(WindowRotationListener windowRotationListener);

        void destroy();

        int getWindowRotation();

        void removeWindowRotationListener(WindowRotationListener windowRotationListener);
    }

    public interface WindowRotationListener {
        void onWindowRotation(int i);
    }

    public static void setWindowHostActivityProvider(@Nullable IContextProvider provider) {
        windowHostActivityProvider = provider;
    }

    @Nonnull
    public static Context wrapGetRotationContext(@Nonnull Context context) {
        IContextProvider iContextProvider;
        Context providedContext;
        if (!(context instanceof Activity) && (iContextProvider = windowHostActivityProvider) != null && (providedContext = iContextProvider.getWindowHostActivityContext()) != null) {
            return providedContext;
        }
        return context;
    }

    public static void setWindowContext(@Nullable WindowContext windowContext2) {
        windowContext = windowContext2;
    }

    @Nullable
    public static WindowContext getWindowContext() {
        return windowContext;
    }
}
