package im.uwrkaxlmjj.ui.hui.adapter.pageAdapter;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AdapterLoadMoreView extends FrameLayout implements AdapterStateView {
    protected int mState;
    protected View progressBar;
    protected MryTextView tv;

    public AdapterLoadMoreView(Context context) {
        this(context, null);
    }

    public AdapterLoadMoreView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public AdapterLoadMoreView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mState = 0;
        init(context);
    }

    protected void init(Context context) {
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        setLayoutParams(new ViewGroup.LayoutParams(-1, AndroidUtilities.dp(70.0f)));
        LinearLayout parent = new LinearLayout(context);
        parent.setOrientation(0);
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.progressBar = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(20.0f));
        ((RadialProgressView) this.progressBar).setProgressColor(Theme.getColor(Theme.key_actionBarTabActiveText));
        parent.addView(this.progressBar, LayoutHelper.createLinear(28, 28, 16, 0, 0, 3, 0));
        MryTextView mryTextView = new MryTextView(context);
        this.tv = mryTextView;
        mryTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
        parent.addView(this.tv, LayoutHelper.createLinear(-2, -2, 16, 3, 0, 0, 0));
        addView(parent, LayoutHelper.createFrame(-2, -2, 17));
        reset();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public Context getContexts() {
        return getContext();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public View getView() {
        return this;
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void show() {
        updateState(this.mState);
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void updateState(int state) {
        if (this.mState == state) {
            return;
        }
        this.mState = state;
        if (state == 0) {
            reset();
            return;
        }
        if (state == 2) {
            reset();
            return;
        }
        if (state == 3) {
            loadMoreStart();
        } else if (state == 4) {
            loadMoreFailed(LocaleController.getString("LoadDataErrorDefault", R.string.LoadDataErrorDefault));
        } else if (state == 5) {
            loadMoreNoMoreData();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public int getState() {
        return this.mState;
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void reset() {
        this.mState = 0;
        post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.-$$Lambda$AdapterLoadMoreView$F2DORgd9QjrcUdJ3znZqAB5qyhI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$reset$0$AdapterLoadMoreView();
            }
        });
    }

    public /* synthetic */ void lambda$reset$0$AdapterLoadMoreView() {
        this.progressBar.setVisibility(8);
        this.tv.setText(LocaleController.getString("LoadMore", R.string.LoadMore));
        this.tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void loadMoreStart() {
        this.mState = 3;
        post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.-$$Lambda$AdapterLoadMoreView$nAT-D5FJ4IQVLndAaG_XCKXw8wo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadMoreStart$1$AdapterLoadMoreView();
            }
        });
    }

    public /* synthetic */ void lambda$loadMoreStart$1$AdapterLoadMoreView() {
        this.progressBar.setVisibility(0);
        this.tv.setText(LocaleController.getString("Loading", R.string.Loading));
        this.tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void loadMoreFinish() {
        reset();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void loadMoreFailed(final CharSequence failedReason) {
        this.mState = 4;
        post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.-$$Lambda$AdapterLoadMoreView$GsQCtH5wbUo-EDe_VsYcM7gnbSM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadMoreFailed$2$AdapterLoadMoreView(failedReason);
            }
        });
    }

    public /* synthetic */ void lambda$loadMoreFailed$2$AdapterLoadMoreView(CharSequence failedReason) {
        this.progressBar.setVisibility(8);
        this.tv.setText(((Object) failedReason) + "");
        this.tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText5));
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.AdapterStateView
    public void loadMoreNoMoreData() {
        this.mState = 5;
        post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.-$$Lambda$AdapterLoadMoreView$OA929LpDE8nj7PS_s59KNzhi6Gc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadMoreNoMoreData$3$AdapterLoadMoreView();
            }
        });
    }

    public /* synthetic */ void lambda$loadMoreNoMoreData$3$AdapterLoadMoreView() {
        this.progressBar.setVisibility(8);
        this.tv.setText(LocaleController.getString("LoadCompleted", R.string.LoadCompleted));
        this.tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
    }
}
