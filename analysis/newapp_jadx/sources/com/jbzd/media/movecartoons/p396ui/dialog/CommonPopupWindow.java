package com.jbzd.media.movecartoons.p396ui.dialog;

import android.content.Context;
import android.view.View;
import android.widget.PopupWindow;
import com.jbzd.media.movecartoons.p396ui.dialog.PopupController;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001:\u0002\u0013\u0014B\u0011\b\u0016\u0012\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000e\u0010\u000fB\u0011\b\u0012\u0012\u0006\u0010\u0011\u001a\u00020\u0010¢\u0006\u0004\b\u000e\u0010\u0012J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR\u0019\u0010\n\u001a\u00020\t8\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow;", "Landroid/widget/PopupWindow;", "", "getWidth", "()I", "getHeight", "", "dismiss", "()V", "Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;", "controller", "Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;", "getController", "()Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;", "<init>", "(Lcom/jbzd/media/movecartoons/ui/dialog/PopupController;)V", "Landroid/content/Context;", "context", "(Landroid/content/Context;)V", "Builder", "ViewInterface", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommonPopupWindow extends PopupWindow {

    @NotNull
    private final PopupController controller;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J!\u0010\u0007\u001a\u00020\u00062\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u0004H&¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$ViewInterface;", "", "Landroid/view/View;", "view", "", "layoutResId", "", "getChildView", "(Landroid/view/View;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface ViewInterface {
        void getChildView(@Nullable View view, int layoutResId);
    }

    public /* synthetic */ CommonPopupWindow(Context context, DefaultConstructorMarker defaultConstructorMarker) {
        this(context);
    }

    public CommonPopupWindow(@NotNull PopupController controller) {
        Intrinsics.checkNotNullParameter(controller, "controller");
        this.controller = controller;
    }

    @Override // android.widget.PopupWindow
    public void dismiss() {
        super.dismiss();
        this.controller.setBackGroundLevel(1.0f);
    }

    @NotNull
    public final PopupController getController() {
        return this.controller;
    }

    @Override // android.widget.PopupWindow
    public int getHeight() {
        View mPopupView = this.controller.getMPopupView();
        if (mPopupView == null) {
            return 0;
        }
        return mPopupView.getMeasuredHeight();
    }

    @Override // android.widget.PopupWindow
    public int getWidth() {
        View mPopupView = this.controller.getMPopupView();
        if (mPopupView == null) {
            return 0;
        }
        return mPopupView.getMeasuredWidth();
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010#\u001a\u00020\"¢\u0006\u0004\b$\u0010%J\u0015\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0015\u0010\u0004\u001a\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\u0004\u0010\bJ\u0017\u0010\u000b\u001a\u00020\u00002\b\u0010\n\u001a\u0004\u0018\u00010\t¢\u0006\u0004\b\u000b\u0010\fJ\u001d\u0010\u000f\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u00022\u0006\u0010\u000e\u001a\u00020\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0015\u0010\u0013\u001a\u00020\u00002\u0006\u0010\u0012\u001a\u00020\u0011¢\u0006\u0004\b\u0013\u0010\u0014J\u0015\u0010\u0017\u001a\u00020\u00002\u0006\u0010\u0016\u001a\u00020\u0015¢\u0006\u0004\b\u0017\u0010\u0018J\u0015\u0010\u001a\u001a\u00020\u00002\u0006\u0010\u0019\u001a\u00020\u0002¢\u0006\u0004\b\u001a\u0010\u0005J\r\u0010\u001c\u001a\u00020\u001b¢\u0006\u0004\b\u001c\u0010\u001dR\u0016\u0010\u001f\u001a\u00020\u001e8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001f\u0010 R\u0018\u0010\n\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\n\u0010!¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "", "", "layoutResId", "setView", "(I)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "Landroid/view/View;", "view", "(Landroid/view/View;)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$ViewInterface;", "listener", "setViewOnclickListener", "(Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$ViewInterface;)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "width", "height", "setWidthAndHeight", "(II)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "", "level", "setBackGroundLevel", "(F)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "", "touchable", "setOutsideTouchable", "(Z)Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$Builder;", "animationStyle", "setAnimationStyle", "Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow;", "builder", "()Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow;", "Lcom/jbzd/media/movecartoons/ui/dialog/PopupController$PopupParams;", VideoListActivity.KEY_PARAMS, "Lcom/jbzd/media/movecartoons/ui/dialog/PopupController$PopupParams;", "Lcom/jbzd/media/movecartoons/ui/dialog/CommonPopupWindow$ViewInterface;", "Landroid/content/Context;", "context", "<init>", "(Landroid/content/Context;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Builder {

        @Nullable
        private ViewInterface listener;

        @NotNull
        private final PopupController.PopupParams params;

        public Builder(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            this.params = new PopupController.PopupParams(context);
        }

        @NotNull
        public final CommonPopupWindow builder() {
            CommonPopupWindow commonPopupWindow = new CommonPopupWindow(this.params.getMContext(), null);
            this.params.apply(commonPopupWindow.getController());
            if (this.listener != null && this.params.getLayoutResId() != 0) {
                ViewInterface viewInterface = this.listener;
                Intrinsics.checkNotNull(viewInterface);
                viewInterface.getChildView(commonPopupWindow.getController().getMPopupView(), this.params.getLayoutResId());
            }
            View mPopupView = commonPopupWindow.getController().getMPopupView();
            if (mPopupView != null) {
                Intrinsics.checkNotNullParameter(mPopupView, "<this>");
                mPopupView.measure(View.MeasureSpec.makeMeasureSpec(0, 0), View.MeasureSpec.makeMeasureSpec(0, 0));
            }
            commonPopupWindow.setFocusable(false);
            return commonPopupWindow;
        }

        @NotNull
        public final Builder setAnimationStyle(int animationStyle) {
            this.params.setShowAnim(true);
            this.params.setAnimationStyle(animationStyle);
            return this;
        }

        @NotNull
        public final Builder setBackGroundLevel(float level) {
            this.params.setShowBg(true);
            this.params.setBg_level(level);
            return this;
        }

        @NotNull
        public final Builder setOutsideTouchable(boolean touchable) {
            this.params.setTouchable(touchable);
            return this;
        }

        @NotNull
        public final Builder setView(int layoutResId) {
            this.params.setMView(null);
            this.params.setLayoutResId(layoutResId);
            return this;
        }

        @NotNull
        public final Builder setViewOnclickListener(@Nullable ViewInterface listener) {
            this.listener = listener;
            return this;
        }

        @NotNull
        public final Builder setWidthAndHeight(int width, int height) {
            this.params.setMWidth(width);
            this.params.setMHeight(height);
            return this;
        }

        @NotNull
        public final Builder setView(@NotNull View view) {
            Intrinsics.checkNotNullParameter(view, "view");
            this.params.setMView(view);
            this.params.setLayoutResId(0);
            return this;
        }
    }

    private CommonPopupWindow(Context context) {
        this.controller = new PopupController(context, this);
    }
}
