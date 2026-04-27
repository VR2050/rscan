package im.uwrkaxlmjj.ui.hui.views;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.blankj.utilcode.util.ColorUtils;
import com.google.android.gms.common.ConnectionResult;
import com.scwang.smartrefresh.layout.api.RefreshHeader;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NormalRefreshHeader extends InternalAbstract implements RefreshHeader {
    private ImageView arrowView;
    private RadialProgressView progressBar;
    private MryTextView tvState;

    public NormalRefreshHeader(Context context) {
        this(context, null);
    }

    public NormalRefreshHeader(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public NormalRefreshHeader(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setGravity(17);
        linearLayout.setOrientation(0);
        linearLayout.setMinimumHeight(AndroidUtilities.dp(60.0f));
        addView(linearLayout, LayoutHelper.createRelative(-1, -2));
        FrameLayout frameLayout = new FrameLayout(context);
        linearLayout.addView(frameLayout);
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.progressBar = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(15.0f));
        this.progressBar.setStrokeWidth(1.5f);
        this.progressBar.setProgressColor(ColorUtils.getColor(R.color.color_FF2ECEFD));
        this.progressBar.setVisibility(8);
        frameLayout.addView(this.progressBar, LayoutHelper.createFrame(23, 23, 17));
        ImageView imageView = new ImageView(context);
        this.arrowView = imageView;
        imageView.setImageResource(R.id.ic_pull_down_to_refresh);
        frameLayout.addView(this.arrowView, LayoutHelper.createFrame(20, 20, 17));
        MryTextView mryTextView = new MryTextView(context);
        this.tvState = mryTextView;
        mryTextView.setTextSize(13.0f);
        this.tvState.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        linearLayout.addView(this.tvState, LayoutHelper.createLinear(-2, -2, 5.0f, 0.0f, 0.0f, 0.0f));
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public void onStartAnimator(RefreshLayout refreshLayout, int height, int maxDragHeight) {
        super.onStartAnimator(refreshLayout, height, maxDragHeight);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public int onFinish(RefreshLayout layout, boolean success) {
        super.onFinish(layout, success);
        return ConnectionResult.DRIVE_EXTERNAL_STORAGE_REQUIRED;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.views.NormalRefreshHeader$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState;

        static {
            int[] iArr = new int[RefreshState.values().length];
            $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState = iArr;
            try {
                iArr[RefreshState.None.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullDownToRefresh.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.ReleaseToRefresh.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.Refreshing.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.RefreshReleased.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullDownCanceled.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.RefreshFinish.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.listener.OnStateChangedListener
    public void onStateChanged(RefreshLayout refreshLayout, RefreshState oldState, RefreshState newState) {
        switch (AnonymousClass1.$SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[newState.ordinal()]) {
            case 1:
            case 2:
                this.arrowView.setVisibility(0);
                this.progressBar.setVisibility(8);
                this.arrowView.animate().rotation(0.0f);
                this.tvState.setText(LocaleController.getString(R.string.RefreshHeaderGameHallPullDownToRefresh));
                break;
            case 3:
                this.arrowView.animate().rotation(180.0f);
                this.tvState.setText(LocaleController.getString(R.string.RefreshHeaderGameHallReleaseToRefresh));
                break;
            case 4:
            case 5:
                this.arrowView.setVisibility(8);
                this.progressBar.setVisibility(0);
                this.tvState.setText(LocaleController.getString(R.string.RefreshHeaderGameHallIsRefreshing));
                break;
            case 6:
            case 7:
                this.arrowView.animate().rotation(0.0f);
                break;
        }
    }
}
