package p426f.p427a.p428a;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.NinePatchDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.CheckResult;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.ContextCompat;
import es.dmoral.toasty.R$color;
import es.dmoral.toasty.R$drawable;
import es.dmoral.toasty.R$id;
import es.dmoral.toasty.R$layout;

@SuppressLint({"InflateParams"})
/* renamed from: f.a.a.a */
/* loaded from: classes2.dex */
public class C4325a {

    /* renamed from: a */
    public static final Typeface f11166a;

    /* renamed from: b */
    public static Typeface f11167b;

    /* renamed from: c */
    public static int f11168c;

    /* renamed from: d */
    public static boolean f11169d;

    /* renamed from: e */
    public static boolean f11170e;

    /* renamed from: f */
    public static Toast f11171f;

    static {
        Typeface create = Typeface.create("sans-serif-condensed", 0);
        f11166a = create;
        f11167b = create;
        f11168c = 16;
        f11169d = true;
        f11170e = true;
        f11171f = null;
    }

    @CheckResult
    @SuppressLint({"ShowToast"})
    /* renamed from: a */
    public static Toast m4898a(@NonNull Context context, @NonNull CharSequence charSequence, Drawable drawable, @ColorInt int i2, @ColorInt int i3, int i4, boolean z, boolean z2) {
        Drawable drawable2;
        Toast makeText = Toast.makeText(context, "", i4);
        View inflate = ((LayoutInflater) context.getSystemService("layout_inflater")).inflate(R$layout.toast_layout, (ViewGroup) null);
        ImageView imageView = (ImageView) inflate.findViewById(R$id.toast_icon);
        TextView textView = (TextView) inflate.findViewById(R$id.toast_text);
        if (z2) {
            drawable2 = (NinePatchDrawable) AppCompatResources.getDrawable(context, R$drawable.toast_frame);
            drawable2.setColorFilter(i2, PorterDuff.Mode.SRC_IN);
        } else {
            drawable2 = AppCompatResources.getDrawable(context, R$drawable.toast_frame);
        }
        inflate.setBackground(drawable2);
        if (!z) {
            imageView.setVisibility(8);
        } else {
            if (drawable == null) {
                throw new IllegalArgumentException("Avoid passing 'icon' as null if 'withIcon' is set to true");
            }
            if (f11169d) {
                drawable.setColorFilter(i3, PorterDuff.Mode.SRC_IN);
            }
            imageView.setBackground(drawable);
        }
        textView.setText(charSequence);
        textView.setTextColor(i3);
        textView.setTypeface(f11167b);
        textView.setTextSize(2, f11168c);
        makeText.setView(inflate);
        if (!f11170e) {
            Toast toast = f11171f;
            if (toast != null) {
                toast.cancel();
            }
            f11171f = makeText;
        }
        return makeText;
    }

    @CheckResult
    /* renamed from: b */
    public static Toast m4899b(@NonNull Context context, @NonNull CharSequence charSequence) {
        return m4900c(context, charSequence, 0, true);
    }

    @CheckResult
    /* renamed from: c */
    public static Toast m4900c(@NonNull Context context, @NonNull CharSequence charSequence, int i2, boolean z) {
        return m4898a(context, charSequence, AppCompatResources.getDrawable(context, R$drawable.ic_clear_white_24dp), ContextCompat.getColor(context, R$color.errorColor), ContextCompat.getColor(context, R$color.defaultTextColor), i2, z, true);
    }

    @CheckResult
    /* renamed from: d */
    public static Toast m4901d(@NonNull Context context, @NonNull CharSequence charSequence) {
        return m4898a(context, charSequence, AppCompatResources.getDrawable(context, R$drawable.ic_info_outline_white_24dp), ContextCompat.getColor(context, R$color.infoColor), ContextCompat.getColor(context, R$color.defaultTextColor), 0, true, true);
    }

    @CheckResult
    /* renamed from: e */
    public static Toast m4902e(@NonNull Context context, @NonNull CharSequence charSequence) {
        return m4903f(context, charSequence, 0, true);
    }

    @CheckResult
    /* renamed from: f */
    public static Toast m4903f(@NonNull Context context, @NonNull CharSequence charSequence, int i2, boolean z) {
        return m4898a(context, charSequence, AppCompatResources.getDrawable(context, R$drawable.ic_check_white_24dp), ContextCompat.getColor(context, R$color.successColor), ContextCompat.getColor(context, R$color.defaultTextColor), i2, z, true);
    }

    @CheckResult
    /* renamed from: g */
    public static Toast m4904g(@NonNull Context context, @NonNull CharSequence charSequence) {
        return m4906i(context, charSequence, 0, true);
    }

    @CheckResult
    /* renamed from: h */
    public static Toast m4905h(@NonNull Context context, @NonNull CharSequence charSequence, int i2) {
        return m4906i(context, charSequence, i2, true);
    }

    @CheckResult
    /* renamed from: i */
    public static Toast m4906i(@NonNull Context context, @NonNull CharSequence charSequence, int i2, boolean z) {
        return m4898a(context, charSequence, AppCompatResources.getDrawable(context, R$drawable.ic_error_outline_white_24dp), ContextCompat.getColor(context, R$color.warningColor), ContextCompat.getColor(context, R$color.defaultTextColor), i2, z, true);
    }
}
