package io.openinstall.sdk;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.view.GravityCompat;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class az {
    public static void a() {
        b();
    }

    public static void a(Activity activity) {
        Context contextD;
        try {
            if (!e()) {
                new Handler(Looper.getMainLooper()).post(new ba(activity));
                return;
            }
            if (b((Context) activity)) {
                contextD = activity;
            } else {
                Context contextC = c();
                contextD = contextC != null ? contextC : d();
            }
            if (contextD == null) {
                as.a().b(false);
                return;
            }
            if (!b(contextD)) {
                as.a().b(false);
            } else if (a(contextD)) {
                as.a().b(false);
            } else {
                as.a().a(true);
                a(contextD, as.a().k());
            }
        } catch (Exception e) {
        }
    }

    private static void a(Context context, bd bdVar) {
        Dialog dialog = new Dialog(context, Build.VERSION.SDK_INT >= 21 ? R.style.Theme.Material.Light.Dialog.Alert : 0);
        dialog.requestWindowFeature(1);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        linearLayout.setBackgroundColor(-1);
        linearLayout.setPadding(60, 40, 60, 40);
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, -2);
        layoutParams.setMargins(80, 80, 80, 40);
        linearLayout.setLayoutParams(layoutParams);
        RelativeLayout relativeLayout = new RelativeLayout(context);
        LinearLayout.LayoutParams layoutParams2 = new LinearLayout.LayoutParams(-1, -2);
        layoutParams2.setMargins(0, 0, 0, 30);
        relativeLayout.setLayoutParams(layoutParams2);
        LinearLayout linearLayout2 = new LinearLayout(context);
        linearLayout2.setOrientation(0);
        LinearLayout.LayoutParams layoutParams3 = new LinearLayout.LayoutParams(-1, -2);
        layoutParams3.gravity = 17;
        linearLayout2.setLayoutParams(layoutParams3);
        if (bdVar.c()) {
            ImageView imageView = new ImageView(context);
            LinearLayout.LayoutParams layoutParams4 = new LinearLayout.LayoutParams(100, 100);
            layoutParams4.setMargins(0, 0, 20, 0);
            imageView.setLayoutParams(layoutParams4);
            try {
                imageView.setImageResource(context.getApplicationInfo().icon);
            } catch (Exception e) {
                imageView.setImageResource(R.drawable.ic_dialog_info);
            }
            imageView.setScaleType(ImageView.ScaleType.CENTER_CROP);
            linearLayout2.addView(imageView);
        }
        TextView textView = new TextView(context);
        LinearLayout.LayoutParams layoutParams5 = new LinearLayout.LayoutParams(-2, -2);
        layoutParams5.gravity = 16;
        textView.setLayoutParams(layoutParams5);
        textView.setText(bdVar.d());
        textView.setTextSize(2, 18.0f);
        textView.setTextColor(-16777216);
        textView.setTypeface(null, 1);
        textView.setPadding(0, 0, 50, 0);
        linearLayout2.addView(textView);
        ImageView imageView2 = new ImageView(context);
        RelativeLayout.LayoutParams layoutParams6 = new RelativeLayout.LayoutParams(66, 66);
        layoutParams6.addRule(11);
        layoutParams6.addRule(10);
        imageView2.setLayoutParams(layoutParams6);
        imageView2.setImageResource(R.drawable.btn_dialog);
        imageView2.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        imageView2.setOnClickListener(new bb(dialog));
        relativeLayout.addView(linearLayout2);
        if (bdVar.b()) {
            relativeLayout.addView(imageView2);
        }
        TextView textView2 = new TextView(context);
        LinearLayout.LayoutParams layoutParams7 = new LinearLayout.LayoutParams(-1, -2);
        layoutParams7.setMargins(0, 0, 0, 40);
        textView2.setLayoutParams(layoutParams7);
        textView2.setText(bdVar.e());
        textView2.setTextSize(2, 16.0f);
        textView2.setTextColor(-16777216);
        textView2.setLineSpacing(8.0f, 1.0f);
        Button button = new Button(context);
        LinearLayout.LayoutParams layoutParams8 = new LinearLayout.LayoutParams(-2, 100);
        layoutParams8.gravity = GravityCompat.END;
        layoutParams8.setMargins(0, 0, 0, 0);
        button.setLayoutParams(layoutParams8);
        button.setText(bdVar.f());
        button.setTextSize(2, 18.0f);
        button.setTextColor(-1);
        button.setPadding(80, 10, 80, 10);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setColor(Color.parseColor("#42A0FD"));
        gradientDrawable.setCornerRadius(20.0f);
        button.setBackground(gradientDrawable);
        button.setOnClickListener(new bc(bdVar, context, dialog));
        linearLayout.addView(relativeLayout);
        linearLayout.addView(textView2);
        linearLayout.addView(button);
        dialog.setContentView(linearLayout);
        dialog.setCanceledOnTouchOutside(false);
        Window window = dialog.getWindow();
        if (window != null) {
            window.setLayout(-2, -2);
            window.setGravity(17);
        }
        dialog.show();
    }

    private static boolean a(Context context) {
        if (context == null) {
            return false;
        }
        if (a(context.getClass().getName())) {
            return true;
        }
        return (context instanceof Activity) && b((Activity) context);
    }

    private static boolean a(View view) {
        if (view == null) {
            return false;
        }
        if (view.getClass().getName().contains("Dialog") || view.getClass().getName().contains("AlertDialog")) {
            return true;
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                if (a(viewGroup.getChildAt(i))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean a(String str) {
        String[] strArr = {"Privacy", "privacy", "Policy", "policy", "Agreement", "agreement", "Terms", "terms", "Consent", "consent", "Splash", "splash"};
        for (int i = 0; i < 12; i++) {
            if (str.contains(strArr[i])) {
                if (!ec.a) {
                    return true;
                }
                ec.a("检测到包含隐私政策关键词的Activity: " + str, new Object[0]);
                return true;
            }
        }
        return false;
    }

    private static void b() {
        a(as.a().d());
    }

    private static boolean b(Activity activity) {
        try {
            if (activity.getWindow() == null || activity.getWindow().getDecorView() == null) {
                return false;
            }
            return a(activity.getWindow().getDecorView());
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean b(Context context) {
        if (context != null && (context instanceof Activity)) {
            Activity activity = (Activity) context;
            try {
                if (activity.isFinishing() || activity.getWindow() == null || activity.getWindow().getDecorView() == null || activity.getWindow().getDecorView().getWindowToken() == null) {
                    return false;
                }
                return !activity.isChangingConfigurations();
            } catch (Exception e) {
            }
        }
        return false;
    }

    private static Context c() {
        return as.a().c();
    }

    private static Context d() {
        try {
            Class<?> cls = Class.forName("android.app.ActivityThread");
            Object objInvoke = cls.getMethod("getActivities", new Class[0]).invoke(cls.getMethod("currentActivityThread", new Class[0]).invoke(null, new Object[0]), new Object[0]);
            if (objInvoke instanceof List) {
                for (Object obj : (List) objInvoke) {
                    if (obj != null) {
                        Object objInvoke2 = obj.getClass().getMethod("getActivity", new Class[0]).invoke(obj, new Object[0]);
                        if (objInvoke2 instanceof Activity) {
                            Activity activity = (Activity) objInvoke2;
                            if (!activity.isFinishing() && b((Context) activity)) {
                                return activity;
                            }
                        } else {
                            continue;
                        }
                    }
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    private static boolean e() {
        return Looper.myLooper() == Looper.getMainLooper();
    }
}
