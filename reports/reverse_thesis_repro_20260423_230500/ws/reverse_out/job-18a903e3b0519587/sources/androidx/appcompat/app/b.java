package androidx.appcompat.app;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.KeyEvent;
import android.view.View;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.appcompat.app.AlertController;
import d.AbstractC0502a;

/* JADX INFO: loaded from: classes.dex */
public class b extends r implements DialogInterface {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final AlertController f3125g;

    public static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final AlertController.b f3126a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f3127b;

        public a(Context context) {
            this(context, b.n(context, 0));
        }

        public b a() {
            b bVar = new b(this.f3126a.f3085a, this.f3127b);
            this.f3126a.a(bVar.f3125g);
            bVar.setCancelable(this.f3126a.f3102r);
            if (this.f3126a.f3102r) {
                bVar.setCanceledOnTouchOutside(true);
            }
            bVar.setOnCancelListener(this.f3126a.f3103s);
            bVar.setOnDismissListener(this.f3126a.f3104t);
            DialogInterface.OnKeyListener onKeyListener = this.f3126a.f3105u;
            if (onKeyListener != null) {
                bVar.setOnKeyListener(onKeyListener);
            }
            return bVar;
        }

        public Context b() {
            return this.f3126a.f3085a;
        }

        public a c(ListAdapter listAdapter, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3107w = listAdapter;
            bVar.f3108x = onClickListener;
            return this;
        }

        public a d(View view) {
            this.f3126a.f3091g = view;
            return this;
        }

        public a e(Drawable drawable) {
            this.f3126a.f3088d = drawable;
            return this;
        }

        public a f(CharSequence[] charSequenceArr, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3106v = charSequenceArr;
            bVar.f3108x = onClickListener;
            return this;
        }

        public a g(CharSequence charSequence) {
            this.f3126a.f3092h = charSequence;
            return this;
        }

        public a h(CharSequence charSequence, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3096l = charSequence;
            bVar.f3098n = onClickListener;
            return this;
        }

        public a i(CharSequence charSequence, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3099o = charSequence;
            bVar.f3101q = onClickListener;
            return this;
        }

        public a j(DialogInterface.OnKeyListener onKeyListener) {
            this.f3126a.f3105u = onKeyListener;
            return this;
        }

        public a k(CharSequence charSequence, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3093i = charSequence;
            bVar.f3095k = onClickListener;
            return this;
        }

        public a l(ListAdapter listAdapter, int i3, DialogInterface.OnClickListener onClickListener) {
            AlertController.b bVar = this.f3126a;
            bVar.f3107w = listAdapter;
            bVar.f3108x = onClickListener;
            bVar.f3078I = i3;
            bVar.f3077H = true;
            return this;
        }

        public a m(CharSequence charSequence) {
            this.f3126a.f3090f = charSequence;
            return this;
        }

        public a(Context context, int i3) {
            this.f3126a = new AlertController.b(new ContextThemeWrapper(context, b.n(context, i3)));
            this.f3127b = i3;
        }
    }

    protected b(Context context, int i3) {
        super(context, n(context, i3));
        this.f3125g = new AlertController(getContext(), this, getWindow());
    }

    static int n(Context context, int i3) {
        if (((i3 >>> 24) & 255) >= 1) {
            return i3;
        }
        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(AbstractC0502a.f8800l, typedValue, true);
        return typedValue.resourceId;
    }

    public ListView m() {
        return this.f3125g.d();
    }

    @Override // androidx.appcompat.app.r, androidx.activity.i, android.app.Dialog
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f3125g.e();
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public boolean onKeyDown(int i3, KeyEvent keyEvent) {
        if (this.f3125g.f(i3, keyEvent)) {
            return true;
        }
        return super.onKeyDown(i3, keyEvent);
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public boolean onKeyUp(int i3, KeyEvent keyEvent) {
        if (this.f3125g.g(i3, keyEvent)) {
            return true;
        }
        return super.onKeyUp(i3, keyEvent);
    }

    @Override // androidx.appcompat.app.r, android.app.Dialog
    public void setTitle(CharSequence charSequence) {
        super.setTitle(charSequence);
        this.f3125g.p(charSequence);
    }
}
