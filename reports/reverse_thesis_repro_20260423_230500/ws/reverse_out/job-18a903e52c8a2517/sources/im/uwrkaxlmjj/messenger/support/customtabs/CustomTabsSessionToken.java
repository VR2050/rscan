package im.uwrkaxlmjj.messenger.support.customtabs;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import androidx.core.app.BundleCompat;
import im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback;

/* JADX INFO: loaded from: classes2.dex */
public class CustomTabsSessionToken {
    private static final String TAG = "CustomTabsSessionToken";
    private final CustomTabsCallback mCallback = new CustomTabsCallback() { // from class: im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsSessionToken.1
        @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback
        public void onNavigationEvent(int navigationEvent, Bundle extras) {
            try {
                CustomTabsSessionToken.this.mCallbackBinder.onNavigationEvent(navigationEvent, extras);
            } catch (RemoteException e) {
                Log.e(CustomTabsSessionToken.TAG, "RemoteException during ICustomTabsCallback transaction");
            }
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback
        public void extraCallback(String callbackName, Bundle args) {
            try {
                CustomTabsSessionToken.this.mCallbackBinder.extraCallback(callbackName, args);
            } catch (RemoteException e) {
                Log.e(CustomTabsSessionToken.TAG, "RemoteException during ICustomTabsCallback transaction");
            }
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback
        public void onMessageChannelReady(Bundle extras) {
            try {
                CustomTabsSessionToken.this.mCallbackBinder.onMessageChannelReady(extras);
            } catch (RemoteException e) {
                Log.e(CustomTabsSessionToken.TAG, "RemoteException during ICustomTabsCallback transaction");
            }
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.CustomTabsCallback
        public void onPostMessage(String message, Bundle extras) {
            try {
                CustomTabsSessionToken.this.mCallbackBinder.onPostMessage(message, extras);
            } catch (RemoteException e) {
                Log.e(CustomTabsSessionToken.TAG, "RemoteException during ICustomTabsCallback transaction");
            }
        }
    };
    private final ICustomTabsCallback mCallbackBinder;

    static class DummyCallback extends ICustomTabsCallback.Stub {
        DummyCallback() {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback
        public void onNavigationEvent(int navigationEvent, Bundle extras) {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback
        public void extraCallback(String callbackName, Bundle args) {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback
        public void onMessageChannelReady(Bundle extras) {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback
        public void onPostMessage(String message, Bundle extras) {
        }

        @Override // im.uwrkaxlmjj.messenger.support.customtabs.ICustomTabsCallback.Stub, android.os.IInterface
        public IBinder asBinder() {
            return this;
        }
    }

    public static CustomTabsSessionToken getSessionTokenFromIntent(Intent intent) {
        Bundle b = intent.getExtras();
        IBinder binder = BundleCompat.getBinder(b, CustomTabsIntent.EXTRA_SESSION);
        if (binder == null) {
            return null;
        }
        return new CustomTabsSessionToken(ICustomTabsCallback.Stub.asInterface(binder));
    }

    public static CustomTabsSessionToken createDummySessionTokenForTesting() {
        return new CustomTabsSessionToken(new DummyCallback());
    }

    CustomTabsSessionToken(ICustomTabsCallback callbackBinder) {
        this.mCallbackBinder = callbackBinder;
    }

    IBinder getCallbackBinder() {
        return this.mCallbackBinder.asBinder();
    }

    public int hashCode() {
        return getCallbackBinder().hashCode();
    }

    public boolean equals(Object o) {
        if (!(o instanceof CustomTabsSessionToken)) {
            return false;
        }
        CustomTabsSessionToken token = (CustomTabsSessionToken) o;
        return token.getCallbackBinder().equals(this.mCallbackBinder.asBinder());
    }

    public CustomTabsCallback getCallback() {
        return this.mCallback;
    }

    public boolean isAssociatedWith(CustomTabsSession session) {
        return session.getBinder().equals(this.mCallbackBinder);
    }
}
