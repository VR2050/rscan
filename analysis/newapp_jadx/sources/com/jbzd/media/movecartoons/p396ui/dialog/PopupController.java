package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.PopupWindow;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u00002\u00020\u0001:\u0001-B\u0011\b\u0016\u0012\u0006\u0010$\u001a\u00020#¢\u0006\u0004\b*\u0010+B\u001b\b\u0016\u0012\u0006\u0010$\u001a\u00020#\u0012\b\u0010\u001b\u001a\u0004\u0018\u00010\u001a¢\u0006\u0004\b*\u0010,J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u001f\u0010\b\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\u000b\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\u000f\u001a\u00020\u00022\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0015\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u0005¢\u0006\u0004\b\u0012\u0010\fJ\u0017\u0010\u0012\u001a\u00020\u00022\b\u0010\u0014\u001a\u0004\u0018\u00010\u0013¢\u0006\u0004\b\u0012\u0010\u0015J\u0015\u0010\u0018\u001a\u00020\u00022\u0006\u0010\u0017\u001a\u00020\u0016¢\u0006\u0004\b\u0018\u0010\u0019R\u0018\u0010\u001b\u001a\u0004\u0018\u00010\u001a8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001b\u0010\u001cR\u0018\u0010\u001d\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR$\u0010\u001f\u001a\u0004\u0018\u00010\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001f\u0010\u001e\u001a\u0004\b \u0010!\"\u0004\b\"\u0010\u0015R\u0016\u0010$\u001a\u00020#8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b$\u0010%R\u0018\u0010'\u001a\u0004\u0018\u00010&8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b'\u0010(R\u0016\u0010\u0011\u001a\u00020\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010)¨\u0006."}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;", "", "", "installContent", "()V", "", "width", "height", "setWidthAndHeight", "(II)V", "animationStyle", "setAnimationStyle", "(I)V", "", "touchable", "setOutsideTouchable", "(Z)V", "layoutResId", "setView", "Landroid/view/View;", "view", "(Landroid/view/View;)V", "", "level", "setBackGroundLevel", "(F)V", "Landroid/widget/PopupWindow;", "popupWindow", "Landroid/widget/PopupWindow;", "mView", "Landroid/view/View;", "mPopupView", "getMPopupView", "()Landroid/view/View;", "setMPopupView", "Landroid/content/Context;", "context", "Landroid/content/Context;", "Landroid/view/Window;", "mWindow", "Landroid/view/Window;", "I", "<init>", "(Landroid/content/Context;)V", "(Landroid/content/Context;Landroid/widget/PopupWindow;)V", "PopupParams", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PopupController {

    @NotNull
    private Context context;
    private int layoutResId;

    @Nullable
    private View mPopupView;

    @Nullable
    private View mView;

    @Nullable
    private Window mWindow;

    @Nullable
    private PopupWindow popupWindow;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u000f\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010&\u001a\u00020%¢\u0006\u0004\b6\u0010+J\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\b\u001a\u00020\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000b\"\u0004\b\f\u0010\rR\"\u0010\u000f\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u000f\u0010\u0011\"\u0004\b\u0012\u0010\u0013R\"\u0010\u0014\u001a\u00020\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0014\u0010\t\u001a\u0004\b\u0015\u0010\u000b\"\u0004\b\u0016\u0010\rR\"\u0010\u0017\u001a\u00020\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0017\u0010\t\u001a\u0004\b\u0018\u0010\u000b\"\u0004\b\u0019\u0010\rR\"\u0010\u001a\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001a\u0010\u0010\u001a\u0004\b\u001a\u0010\u0011\"\u0004\b\u001b\u0010\u0013R\"\u0010\u001c\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001c\u0010\u0010\u001a\u0004\b\u001c\u0010\u0011\"\u0004\b\u001d\u0010\u0013R\"\u0010\u001f\u001a\u00020\u001e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"\"\u0004\b#\u0010$R\"\u0010&\u001a\u00020%8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b&\u0010'\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R$\u0010-\u001a\u0004\u0018\u00010,8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b-\u0010.\u001a\u0004\b/\u00100\"\u0004\b1\u00102R\"\u00103\u001a\u00020\u00078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b3\u0010\t\u001a\u0004\b4\u0010\u000b\"\u0004\b5\u0010\r¨\u00067"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PopupController$PopupParams;", "", "Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;", "controller", "", "apply", "(Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;)V", "", "mWidth", "I", "getMWidth", "()I", "setMWidth", "(I)V", "", "isShowAnim", "Z", "()Z", "setShowAnim", "(Z)V", "animationStyle", "getAnimationStyle", "setAnimationStyle", "mHeight", "getMHeight", "setMHeight", "isShowBg", "setShowBg", "isTouchable", "setTouchable", "", "bg_level", "F", "getBg_level", "()F", "setBg_level", "(F)V", "Landroid/content/Context;", "mContext", "Landroid/content/Context;", "getMContext", "()Landroid/content/Context;", "setMContext", "(Landroid/content/Context;)V", "Landroid/view/View;", "mView", "Landroid/view/View;", "getMView", "()Landroid/view/View;", "setMView", "(Landroid/view/View;)V", "layoutResId", "getLayoutResId", "setLayoutResId", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class PopupParams {
        private int animationStyle;
        private float bg_level;
        private boolean isShowAnim;
        private boolean isShowBg;
        private boolean isTouchable;
        private int layoutResId;

        @NotNull
        private Context mContext;
        private int mHeight;

        @Nullable
        private View mView;
        private int mWidth;

        public PopupParams(@NotNull Context mContext) {
            Intrinsics.checkNotNullParameter(mContext, "mContext");
            this.mContext = mContext;
            this.isTouchable = true;
        }

        public final void apply(@NotNull PopupController controller) {
            Intrinsics.checkNotNullParameter(controller, "controller");
            View view = this.mView;
            if (view != null) {
                controller.setView(view);
            } else {
                int i2 = this.layoutResId;
                if (i2 == 0) {
                    throw new IllegalArgumentException("PopupView's contentView is null");
                }
                controller.setView(i2);
            }
            controller.setWidthAndHeight(this.mWidth, this.mHeight);
            controller.setOutsideTouchable(this.isTouchable);
            if (this.isShowBg) {
                controller.setBackGroundLevel(this.bg_level);
            }
            if (this.isShowAnim) {
                controller.setAnimationStyle(this.animationStyle);
            }
        }

        public final int getAnimationStyle() {
            return this.animationStyle;
        }

        public final float getBg_level() {
            return this.bg_level;
        }

        public final int getLayoutResId() {
            return this.layoutResId;
        }

        @NotNull
        public final Context getMContext() {
            return this.mContext;
        }

        public final int getMHeight() {
            return this.mHeight;
        }

        @Nullable
        public final View getMView() {
            return this.mView;
        }

        public final int getMWidth() {
            return this.mWidth;
        }

        /* renamed from: isShowAnim, reason: from getter */
        public final boolean getIsShowAnim() {
            return this.isShowAnim;
        }

        /* renamed from: isShowBg, reason: from getter */
        public final boolean getIsShowBg() {
            return this.isShowBg;
        }

        /* renamed from: isTouchable, reason: from getter */
        public final boolean getIsTouchable() {
            return this.isTouchable;
        }

        public final void setAnimationStyle(int i2) {
            this.animationStyle = i2;
        }

        public final void setBg_level(float f2) {
            this.bg_level = f2;
        }

        public final void setLayoutResId(int i2) {
            this.layoutResId = i2;
        }

        public final void setMContext(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "<set-?>");
            this.mContext = context;
        }

        public final void setMHeight(int i2) {
            this.mHeight = i2;
        }

        public final void setMView(@Nullable View view) {
            this.mView = view;
        }

        public final void setMWidth(int i2) {
            this.mWidth = i2;
        }

        public final void setShowAnim(boolean z) {
            this.isShowAnim = z;
        }

        public final void setShowBg(boolean z) {
            this.isShowBg = z;
        }

        public final void setTouchable(boolean z) {
            this.isTouchable = z;
        }
    }

    public PopupController(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    private final void installContent() {
        if (this.layoutResId != 0) {
            this.mPopupView = LayoutInflater.from(this.context).inflate(this.layoutResId, (ViewGroup) null);
        } else {
            View view = this.mView;
            if (view != null) {
                this.mPopupView = view;
            }
        }
        PopupWindow popupWindow = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow);
        popupWindow.setContentView(this.mPopupView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setAnimationStyle(int animationStyle) {
        PopupWindow popupWindow = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow);
        popupWindow.setAnimationStyle(animationStyle);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setOutsideTouchable(boolean touchable) {
        PopupWindow popupWindow = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow);
        popupWindow.setBackgroundDrawable(new ColorDrawable(0));
        PopupWindow popupWindow2 = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow2);
        popupWindow2.setOutsideTouchable(touchable);
        PopupWindow popupWindow3 = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow3);
        popupWindow3.setFocusable(touchable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setWidthAndHeight(int width, int height) {
        if (width == 0 || height == 0) {
            PopupWindow popupWindow = this.popupWindow;
            Intrinsics.checkNotNull(popupWindow);
            popupWindow.setWidth(-2);
            PopupWindow popupWindow2 = this.popupWindow;
            Intrinsics.checkNotNull(popupWindow2);
            popupWindow2.setHeight(-2);
            return;
        }
        PopupWindow popupWindow3 = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow3);
        popupWindow3.setWidth(width);
        PopupWindow popupWindow4 = this.popupWindow;
        Intrinsics.checkNotNull(popupWindow4);
        popupWindow4.setHeight(height);
    }

    @Nullable
    public final View getMPopupView() {
        return this.mPopupView;
    }

    public final void setBackGroundLevel(float level) {
        Window window = ((Activity) this.context).getWindow();
        if (window == null) {
            return;
        }
        WindowManager.LayoutParams attributes = window.getAttributes();
        attributes.alpha = level;
        window.setAttributes(attributes);
    }

    public final void setMPopupView(@Nullable View view) {
        this.mPopupView = view;
    }

    public final void setView(int layoutResId) {
        this.mView = null;
        this.layoutResId = layoutResId;
        installContent();
    }

    public PopupController(@NotNull Context context, @Nullable PopupWindow popupWindow) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.popupWindow = popupWindow;
    }

    public final void setView(@Nullable View view) {
        this.mView = view;
        this.layoutResId = 0;
        installContent();
    }
}
