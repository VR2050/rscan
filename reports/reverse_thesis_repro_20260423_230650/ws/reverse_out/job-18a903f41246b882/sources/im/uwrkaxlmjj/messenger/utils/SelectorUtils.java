package im.uwrkaxlmjj.messenger.utils;

import android.R;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.StateListDrawable;
import android.os.AsyncTask;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.FileLog;
import java.io.IOException;
import java.net.URL;

/* JADX INFO: loaded from: classes2.dex */
public class SelectorUtils {
    public static void addSelectorFromDrawable(Context context, int idNormal, int idPress, ImageView iv) {
        StateListDrawable drawable = new StateListDrawable();
        Drawable normal = context.getResources().getDrawable(idNormal);
        Drawable press = context.getResources().getDrawable(idPress);
        drawable.addState(new int[]{R.attr.state_pressed}, press);
        drawable.addState(new int[]{-16842919}, normal);
        iv.setBackgroundDrawable(drawable);
    }

    public static void addSelectorFromDrawable(Context context, int idNormal, int idPress, View button) {
        StateListDrawable drawable = new StateListDrawable();
        Drawable normal = context.getResources().getDrawable(idNormal);
        Drawable press = context.getResources().getDrawable(idPress);
        drawable.addState(new int[]{R.attr.state_pressed}, press);
        drawable.addState(new int[]{-16842919}, normal);
        button.setBackgroundDrawable(drawable);
    }

    public static void addSelectorFromDrawable(Context context, int idNormal, int idPress, int iPressFilterColor, View button) {
        StateListDrawable drawable = new StateListDrawable();
        Drawable normal = context.getResources().getDrawable(idNormal);
        Drawable press = context.getResources().getDrawable(idPress);
        if (press != null) {
            press = DrawableUtils.tintDrawable(press, iPressFilterColor);
        }
        drawable.addState(new int[]{R.attr.state_pressed}, press);
        drawable.addState(new int[]{-16842919}, normal);
        button.setBackgroundDrawable(drawable);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [im.uwrkaxlmjj.messenger.utils.SelectorUtils$1] */
    public static void addSeletorFromNet(final Class clazz, final String normalUrl, final String pressUrl, final ImageView imageView) {
        new AsyncTask<Void, Void, Drawable>() { // from class: im.uwrkaxlmjj.messenger.utils.SelectorUtils.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public Drawable doInBackground(Void... params) {
                StateListDrawable drawable = new StateListDrawable();
                Drawable normal = SelectorUtils.loadImageFromNet(clazz, normalUrl);
                Drawable press = SelectorUtils.loadImageFromNet(clazz, pressUrl);
                drawable.addState(new int[]{R.attr.state_pressed}, press);
                drawable.addState(new int[]{-16842919}, normal);
                return drawable;
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public void onPostExecute(Drawable drawable) {
                super.onPostExecute(drawable);
                imageView.setBackgroundDrawable(drawable);
            }
        }.execute(new Void[0]);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [im.uwrkaxlmjj.messenger.utils.SelectorUtils$2] */
    public static void addSeletorFromNet(final Class clazz, final String normalUrl, final String pressUrl, final Button button) {
        new AsyncTask<Void, Void, Drawable>() { // from class: im.uwrkaxlmjj.messenger.utils.SelectorUtils.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public Drawable doInBackground(Void... params) {
                StateListDrawable drawable = new StateListDrawable();
                Drawable normal = SelectorUtils.loadImageFromNet(clazz, normalUrl);
                Drawable press = SelectorUtils.loadImageFromNet(clazz, pressUrl);
                drawable.addState(new int[]{R.attr.state_pressed}, press);
                drawable.addState(new int[]{-16842919}, normal);
                return drawable;
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public void onPostExecute(Drawable drawable) {
                super.onPostExecute(drawable);
                button.setBackgroundDrawable(drawable);
            }
        }.execute(new Void[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Drawable loadImageFromNet(Class clazz, String netUrl) {
        try {
            Drawable drawable = Drawable.createFromStream(new URL(netUrl).openStream(), "netUrl.jpg");
            return drawable;
        } catch (IOException e) {
            FileLog.e(clazz.getName() + e.getMessage());
            return null;
        }
    }

    public static void addSelectorFromDrawable(Context context, Drawable dNormal, Drawable dPress, View iv) {
        StateListDrawable drawable = new StateListDrawable();
        drawable.addState(new int[]{R.attr.state_pressed}, dPress);
        drawable.addState(new int[]{-16842919}, dNormal);
        iv.setBackgroundDrawable(drawable);
    }
}
