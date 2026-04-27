package im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments;

import android.content.res.ColorStateList;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcPageFollowedPresenter;
import com.blankj.utilcode.util.SpanUtils;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.fc.FcLocationInfoBean;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.decoration.DefaultItemDecoration;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration.SpacesItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.state.ScreenViewState;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcLocationInfoActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageMineActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcReportActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.AutoPlayTool;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryRoundButtonDrawable;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcFollowFragment extends CommFcListFragment implements NotificationCenter.NotificationCenterDelegate, FcItemActionClickListener, BaseFcContract.IFcPageFollowedView, FcDoReplyDialog.OnFcDoReplyListener {
    private PageSelectionAdapter<Object, PageHolder> adapterTopics;
    private AutoPlayTool autoPlayTool;
    private MryEmptyView emptyView;
    private View llAllTopics;
    private FcHomeAdapter mAdapter;
    private BaseFcContract.IFcPageFollowedPresenter mPresenter;
    private SmartRefreshLayout mSmartRefreshLayout;
    private RespFcListBean replyItemModel;
    private RecyclerView rvFcList;
    private RecyclerView rvTopics;
    private FrameLayout rvTopicsParent;
    private RecyclerView.OnScrollListener scrollListenerRvFcList;
    private MryTextView tvAllTopics;
    private String TAG = FcFollowFragment.class.getSimpleName();
    private int[] coord = new int[2];
    private int[] coordedt = new int[2];
    private int pageNo = 0;
    private int replyParentPosition = -1;
    private int replyChildPosition = -1;
    RecyclerView.OnScrollListener rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment.5
        boolean isScroll = false;

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            super.onScrolled(recyclerView, dx, dy);
            if (FcFollowFragment.this.autoPlayTool != null && this.isScroll) {
                FcFollowFragment.this.autoPlayTool.onScrolledAndDeactivate();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            super.onScrollStateChanged(recyclerView, newState);
            this.isScroll = newState != 0;
            if (newState == 0) {
                if (FcFollowFragment.this.mSmartRefreshLayout.getState() == RefreshState.None || FcFollowFragment.this.mSmartRefreshLayout.getState() == RefreshState.RefreshFinish) {
                    FcFollowFragment.this.isActivePlayer(recyclerView);
                }
            }
        }
    };

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment
    protected int getLayoutRes() {
        return R.layout.fragment_fc_page_follow;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment
    protected void initView() {
        this.mSmartRefreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.smartRefreshLayout);
        this.rvFcList = (RecyclerView) this.fragmentView.findViewById(R.attr.rv_fc_list);
        this.rvTopicsParent = (FrameLayout) this.fragmentView.findViewById(R.attr.rvTopicsParent);
        this.mSmartRefreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment.1
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                FcFollowFragment.this.pageNo = 0;
                FcFollowFragment.this.getFcPageList();
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                FcFollowFragment.this.getFcPageList();
            }
        });
        this.layoutManager = new LinearLayoutManager(this.mContext, 1, false);
        this.rvFcList.setLayoutManager(this.layoutManager);
        this.rvFcList.addItemDecoration(new SpacesItemDecoration(AndroidUtilities.dp(7.0f)));
        FcHomeAdapter fcHomeAdapter = new FcHomeAdapter(new ArrayList(), getParentActivity(), getClassGuid(), 3, this);
        this.mAdapter = fcHomeAdapter;
        fcHomeAdapter.setFooterCount(1);
        this.mAdapter.isShowFollowBtn(false);
        this.rvFcList.setAdapter(this.mAdapter);
        this.rvFcList.addOnScrollListener(this.rvScrollListener);
        Theme.getCurrentTheme().isLight();
        this.rvTopics = (RecyclerView) this.fragmentView.findViewById(R.attr.rvTopics);
        this.llAllTopics = this.fragmentView.findViewById(R.attr.llAllTopics);
        this.tvAllTopics = (MryTextView) this.fragmentView.findViewById(R.attr.tvAllTopics);
        this.rvTopicsParent.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.rvTopicsParent.setVisibility(8);
        GradientDrawable gradientDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, new int[]{AndroidUtilities.alphaColor(0.9f, Theme.getColor(Theme.key_windowBackgroundWhite)), Theme.getColor(Theme.key_windowBackgroundWhite)});
        gradientDrawable.setGradientType(0);
        this.llAllTopics.setBackground(gradientDrawable);
        this.llAllTopics.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$kNHeBf2zPI-cwKV2NyRya-Qnvuw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$FcFollowFragment(view);
            }
        });
        float fDp = AndroidUtilities.dp(52.0f) + this.tvAllTopics.getPaint().measureText(this.tvAllTopics.getText().toString(), 0, this.tvAllTopics.getText().toString().length());
        this.rvTopics.setLayoutManager(new LinearLayoutManager(getParentActivity(), 0, 0 == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        this.rvTopics.addItemDecoration(new TopBottomDecoration(AndroidUtilities.dp(15.0f), (int) fDp, false));
        this.rvTopics.addItemDecoration(new DefaultItemDecoration().setDividerColor(0).setDividerWidth(AndroidUtilities.dp(7.0f)));
        this.rvTopics.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter = new PageSelectionAdapter<Object, PageHolder>(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment.3
            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            protected boolean isEnableForChild(PageHolder holder) {
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
                FrameLayout container = new FrameLayout(FcFollowFragment.this.getParentActivity());
                MryTextView tv = new MryTextView(FcFollowFragment.this.getParentActivity());
                tv.setPadding(AndroidUtilities.dp(7.0f), AndroidUtilities.dp(4.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f));
                tv.setGravity(17);
                tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                tv.setSingleLine();
                tv.setTextSize(13.0f);
                container.addView(tv, LayoutHelper.createFrame(-2, -2, 17));
                RecyclerView.LayoutParams lp = new RecyclerView.LayoutParams(-2, -1);
                container.setLayoutParams(lp);
                return new PageHolder(container, 0);
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public void onBindViewHolderForChild(PageHolder holder, int position, Object item) {
                MryTextView tv = (MryTextView) ((ViewGroup) holder.itemView).getChildAt(0);
                MryRoundButtonDrawable topicsBg = new MryRoundButtonDrawable();
                topicsBg.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundGray)));
                topicsBg.setIsRadiusAdjustBounds(true);
                topicsBg.setStrokeWidth(0);
                tv.setBackground(topicsBg);
                SpanUtils.with(tv).append("# ").setForegroundColor(-13709571).append(item.toString()).setForegroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).create();
            }
        };
        this.adapterTopics = pageSelectionAdapter;
        pageSelectionAdapter.setShowLoadMoreViewEnable(false);
        this.rvTopics.setAdapter(this.adapterTopics);
        this.adapterTopics.setData(new ArrayList(Arrays.asList("致敬最可爱的人", "外貌协会交流所", "cosplay爱好协会", "无聊综合症", "有趣的灵魂300斤", "跳舞达人聚焦地", "开久了才知道的事", "不听音乐我会死")));
        initEmptyView();
    }

    public /* synthetic */ void lambda$initView$0$FcFollowFragment(View v) {
        presentFragment(new FcTopicMainActivity());
    }

    private void initEmptyView() {
        ViewGroup flContainer = (ViewGroup) this.fragmentView.findViewById(R.attr.fl_container);
        this.emptyView = new MryEmptyView(this.mContext);
        if (Theme.getCurrentTheme().isLight()) {
            this.emptyView.setBackgroundColor(this.mContext.getResources().getColor(R.color.color_FFF6F7F9));
        } else {
            this.emptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        }
        this.emptyView.attach(flContainer);
        this.emptyView.setEmptyText(LocaleController.getString(R.string.NoFollowedPageDataMessages));
        this.emptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyView.setErrorResId(R.id.img_empty_default);
        this.emptyView.getTextView().setTextColor(this.mContext.getResources().getColor(R.color.color_FFDBC9B8));
        this.emptyView.getBtn().setPrimaryRadiusAdjustBoundsFillStyle();
        this.emptyView.getBtn().setRoundBgGradientColors(new int[]{-4789508, -13187843});
        this.emptyView.getBtn().setStrokeWidth(0);
        this.emptyView.getBtn().setPadding(AndroidUtilities.dp(15.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(15.0f), AndroidUtilities.dp(5.0f));
        this.emptyView.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$4_2BPUMFOwQpCrLOg5iGjA0VhVw
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initEmptyView$1$FcFollowFragment(z);
            }
        });
        flContainer.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
    }

    public /* synthetic */ boolean lambda$initEmptyView$1$FcFollowFragment(boolean isEmptyButton) {
        this.pageNo = 0;
        refreshPageState(true, null);
        getFcPageList();
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment
    protected void initData() {
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcIgnoreOrDeleteItem);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcIgnoreUser);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(UserConfig.selectedAccount).addObserver(this, NotificationCenter.fcDeleteReplyItem);
        this.mPresenter = new FcPageFollowedPresenter(this);
        getDBCache();
        this.pageNo = 0;
        refreshPageState(true, null);
        getFcPageList();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.LazyLoadFragment
    public void onVisible() {
        super.onVisible();
        getParentActivity().getWindow().setSoftInputMode(16);
        VideoPlayerManager.getInstance().resume();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment.4
            @Override // java.lang.Runnable
            public void run() {
                if (FcFollowFragment.this.rvScrollListener != null) {
                    FcFollowFragment.this.rvScrollListener.onScrollStateChanged(FcFollowFragment.this.rvFcList, 0);
                }
            }
        }, 1000L);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.LazyLoadFragment
    public void onInvisible() {
        super.onInvisible();
        if (ScreenViewState.isFullScreen(VideoPlayerManager.getInstance().getmScreenState())) {
            VideoPlayerManager.getInstance().onBackPressed();
        }
        setStopPlayState();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.LazyLoadFragment, androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcIgnoreOrDeleteItem);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcIgnoreUser);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.fcDeleteReplyItem);
        VideoPlayerManager.getInstance().release();
        RecyclerView recyclerView = this.rvFcList;
        if (recyclerView != null) {
            recyclerView.removeOnScrollListener(this.scrollListenerRvFcList);
            this.scrollListenerRvFcList = null;
        }
        PageSelectionAdapter<Object, PageHolder> pageSelectionAdapter = this.adapterTopics;
        if (pageSelectionAdapter != null) {
            pageSelectionAdapter.destroy();
            this.adapterTopics = null;
        }
        BaseFcContract.IFcPageFollowedPresenter iFcPageFollowedPresenter = this.mPresenter;
        if (iFcPageFollowedPresenter != null) {
            iFcPageFollowedPresenter.unSubscribeTask();
        }
    }

    private void refreshPageState(boolean isRefreshing, String errorMsg) {
        if (isRefreshing) {
            this.emptyView.showLoading();
            return;
        }
        if (this.pageNo == 0 && !TextUtils.isEmpty(errorMsg) && this.mAdapter.getDataList().size() <= this.mAdapter.getHeaderFooterCount()) {
            this.emptyView.showError(errorMsg);
            return;
        }
        FcHomeAdapter fcHomeAdapter = this.mAdapter;
        if (fcHomeAdapter != null && fcHomeAdapter.getDataList().size() <= this.mAdapter.getHeaderFooterCount()) {
            this.emptyView.showEmpty();
        } else if (this.emptyView.getCurrentStatus() != 2) {
            this.emptyView.showContent();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int i1;
        int childPosition;
        KLog.d("---------通知" + id);
        if (id == NotificationCenter.fcFollowStatusUpdate) {
            String tag = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag)) {
                long createBy = ((Long) args[1]).longValue();
                boolean isFollow = ((Boolean) args[2]).booleanValue();
                if (isFollow) {
                    this.pageNo = 0;
                    getFcPageList();
                    return;
                }
                int position = -1;
                FcHomeAdapter fcHomeAdapter = this.mAdapter;
                if (fcHomeAdapter != null) {
                    List<RespFcListBean> dataList = fcHomeAdapter.getDataList();
                    int i = 0;
                    while (true) {
                        if (i >= dataList.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean = dataList.get(i);
                        if (respFcListBean == null || respFcListBean.getCreateBy() != createBy) {
                            i++;
                        } else {
                            position = i;
                            break;
                        }
                    }
                }
                if (position != -1) {
                    doFollowAfterViewChange(position, isFollow);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcPermissionStatusUpdate) {
            String tag2 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag2)) {
                long forumId = ((Long) args[1]).longValue();
                int permission = ((Integer) args[2]).intValue();
                int position2 = -1;
                FcHomeAdapter fcHomeAdapter2 = this.mAdapter;
                if (fcHomeAdapter2 != null) {
                    List<RespFcListBean> dataList2 = fcHomeAdapter2.getDataList();
                    int i2 = 0;
                    while (true) {
                        if (i2 >= dataList2.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean2 = dataList2.get(i2);
                        if (respFcListBean2 == null || respFcListBean2.getForumID() != forumId) {
                            i2++;
                        } else {
                            position2 = i2;
                            break;
                        }
                    }
                }
                if (position2 != -1) {
                    doSetItemPermissionAfterViewChange(forumId, permission, position2);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcIgnoreOrDeleteItem) {
            String tag3 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag3)) {
                long forumId2 = ((Long) args[1]).longValue();
                int position3 = -1;
                FcHomeAdapter fcHomeAdapter3 = this.mAdapter;
                if (fcHomeAdapter3 != null && forumId2 > 0) {
                    List<RespFcListBean> dataList3 = fcHomeAdapter3.getDataList();
                    int i3 = 0;
                    while (true) {
                        if (i3 >= dataList3.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean3 = dataList3.get(i3);
                        if (respFcListBean3 == null || respFcListBean3.getForumID() != forumId2) {
                            i3++;
                        } else {
                            position3 = i3;
                            break;
                        }
                    }
                }
                if (position3 != -1) {
                    doDeleteItemAfterViewChange(forumId2, position3);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcLikeStatusUpdate) {
            String tag4 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag4)) {
                FcLikeBean fcLikeBean = (FcLikeBean) args[1];
                boolean isLike = ((Boolean) args[2]).booleanValue();
                int position4 = -1;
                if (this.mAdapter != null && fcLikeBean != null && fcLikeBean.getCommentID() == 0) {
                    List<RespFcListBean> dataList4 = this.mAdapter.getDataList();
                    int i4 = 0;
                    while (true) {
                        if (i4 >= dataList4.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean4 = dataList4.get(i4);
                        if (respFcListBean4 == null || respFcListBean4.getForumID() != fcLikeBean.getForumID()) {
                            i4++;
                        } else {
                            position4 = i4;
                            break;
                        }
                    }
                }
                if (position4 != -1) {
                    doLikeAfterViewChange(position4, isLike, fcLikeBean);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcIgnoreUser) {
            String tag5 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag5)) {
                ArrayList<FcIgnoreUserBean> ignores = (ArrayList) args[1];
                int position5 = -1;
                if (this.mAdapter != null && ignores != null && ignores.size() > 0) {
                    List<RespFcListBean> dataList5 = this.mAdapter.getDataList();
                    int i5 = 0;
                    while (true) {
                        if (i5 >= dataList5.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean5 = dataList5.get(i5);
                        if (respFcListBean5 == null || respFcListBean5.getCreateBy() != ignores.get(0).getUserID()) {
                            i5++;
                        } else {
                            position5 = i5;
                            break;
                        }
                    }
                }
                if (position5 != -1) {
                    doSetIgnoreUserAfterViewChange(true, ignores);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcReplyItem) {
            String tag6 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag6)) {
                FcReplyBean data = (FcReplyBean) args[1];
                int position6 = -1;
                FcHomeAdapter fcHomeAdapter4 = this.mAdapter;
                if (fcHomeAdapter4 != null && data != null) {
                    List<RespFcListBean> dataList6 = fcHomeAdapter4.getDataList();
                    int i6 = 0;
                    while (true) {
                        if (i6 >= dataList6.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean6 = dataList6.get(i6);
                        if (respFcListBean6 == null || respFcListBean6.getForumID() != data.getForumID()) {
                            i6++;
                        } else {
                            position6 = i6;
                            break;
                        }
                    }
                }
                if (position6 != -1) {
                    doReplySuccAfterViewChange(data, position6);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcDeleteReplyItem) {
            String tag7 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag7)) {
                long forumId3 = ((Long) args[1]).longValue();
                long commentId = ((Long) args[2]).longValue();
                int childPosition2 = -1;
                FcHomeAdapter fcHomeAdapter5 = this.mAdapter;
                if (fcHomeAdapter5 != null && forumId3 > 0 && commentId > 0) {
                    List<RespFcListBean> dataList7 = fcHomeAdapter5.getDataList();
                    for (int i7 = 0; i7 < dataList7.size(); i7++) {
                        RespFcListBean respFcListBean7 = dataList7.get(i7);
                        if (respFcListBean7 != null && respFcListBean7.getForumID() == forumId3) {
                            int parentPosition = i7;
                            ArrayList<FcReplyBean> comments = respFcListBean7.getComments();
                            int i12 = 0;
                            while (true) {
                                if (i12 >= comments.size()) {
                                    break;
                                }
                                FcReplyBean replyBean = comments.get(i12);
                                if (replyBean == null || replyBean.getCommentID() != commentId) {
                                    i12++;
                                } else {
                                    childPosition2 = i12;
                                    break;
                                }
                            }
                            i1 = parentPosition;
                            childPosition = childPosition2;
                        }
                    }
                    i1 = -1;
                    childPosition = -1;
                } else {
                    i1 = -1;
                    childPosition = -1;
                }
                if (i1 != -1 && childPosition != -1) {
                    doDeleteReplySuccAfterViewChange(forumId3, commentId, i1, childPosition);
                }
            }
        }
    }

    public void setPageNo(int pageNo) {
        this.pageNo = pageNo;
    }

    public void getFcPageList() {
        long paForumID = this.pageNo == 0 ? 0L : this.mAdapter.getEndListId();
        this.mPresenter.getFcList(20, paForumID);
    }

    private void getDBCache() {
        ArrayList<FollowedFcListBean> queryAll = FcDBHelper.getInstance().getQueryByOrder(FollowedFcListBean.class);
        ArrayList<RespFcListBean> tempList = new ArrayList<>();
        for (FollowedFcListBean followedFcListBean : queryAll) {
            if (followedFcListBean != null) {
                tempList.add(followedFcListBean);
            }
        }
        setData(tempList);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageFollowedView
    public void getFcListSucc(ArrayList<RespFcListBean> data) {
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        if (this.pageNo == 0) {
            refreshDotStatus(2);
            FcDBHelper.getInstance().deleteAll(FollowedFcListBean.class);
        }
        if (data != null) {
            ArrayList<FollowedFcListBean> tempInsertList = new ArrayList<>();
            for (RespFcListBean respFcListBean : data) {
                tempInsertList.add(new FollowedFcListBean(respFcListBean));
            }
            FcDBHelper.getInstance().insertAll(tempInsertList);
        }
        setData(data);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageFollowedView
    public void getFcListFailed(String msg) {
        if (this.pageNo == 0) {
            getDBCache();
        }
        this.mSmartRefreshLayout.finishRefresh();
        this.mSmartRefreshLayout.finishLoadMore();
        FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail));
        refreshPageState(false, msg);
    }

    private void setData(ArrayList<RespFcListBean> mFclistBeanList) {
        if (this.pageNo == 0) {
            if (mFclistBeanList == null || mFclistBeanList.size() == 0) {
                this.mSmartRefreshLayout.setEnableLoadMore(false);
                this.mAdapter.refresh(new ArrayList());
            } else {
                if (mFclistBeanList.size() < 20) {
                    this.mSmartRefreshLayout.setEnableLoadMore(false);
                    mFclistBeanList.add(new RespFcListBean());
                } else {
                    this.mSmartRefreshLayout.setEnableLoadMore(true);
                }
                this.mAdapter.refresh(mFclistBeanList);
                this.pageNo++;
            }
            AutoPlayTool autoPlayTool = this.autoPlayTool;
            if (autoPlayTool != null) {
                autoPlayTool.onRefreshDeactivate();
            }
            refreshPageState(false, null);
            return;
        }
        if (mFclistBeanList == null || mFclistBeanList.size() < 20) {
            mFclistBeanList.add(new RespFcListBean());
            this.mSmartRefreshLayout.setEnableLoadMore(false);
        }
        this.mAdapter.loadMore(mFclistBeanList);
        refreshPageState(false, null);
        if (mFclistBeanList.size() > 0) {
            this.pageNo++;
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onAction(View view, int index, final int position, Object object) {
        if (index == FcHomeAdapter.Index_click_avatar) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model = (RespFcListBean) object;
                if (model.getCreateBy() == getUserConfig().getCurrentUser().id) {
                    onPresentFragment(new FcPageMineActivity());
                    return;
                } else {
                    onPresentFragment(new FcPageOthersActivity(model.getCreatorUser()));
                    return;
                }
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_follow) {
            if (object instanceof RespFcListBean) {
                doFollow(position, (RespFcListBean) object);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_cancel_follow) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model2 = (RespFcListBean) object;
                boolean isFemale = false;
                if (model2.getCreatorUser() != null) {
                    FcUserInfoBean creatorUser = model2.getCreatorUser();
                    if (creatorUser.getSex() == 2) {
                        isFemale = true;
                    }
                }
                FcDialogUtil.chooseCancelFollowedDialog(this, isFemale, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$DNyv5Ukgl16A-0MKC7rzUm6QyiE
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$2$FcFollowFragment(position, model2, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_public) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 1, position);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_private) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 2, position);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_delete) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model3 = (RespFcListBean) object;
                FcDialogUtil.chooseIsDeleteMineItemDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$7HZPDwKZ6z5bfhbyvJdxYQTyPiE
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$3$FcFollowFragment(position, model3, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_shield_item) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model4 = (RespFcListBean) object;
                FcDialogUtil.chooseIsSetOtherFcItemPrivacyDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$uwuSNKLfJU1MZqu0CZ7hwSft89o
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$4$FcFollowFragment(position, model4, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_shield_user) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model5 = (RespFcListBean) object;
                FcDialogUtil.choosePrivacyAllFcDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.-$$Lambda$FcFollowFragment$70rt7BoNmVagaYrwTENsGzs8hZc
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$5$FcFollowFragment(model5, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_pop_report) {
            if (object instanceof RespFcListBean) {
                presentFragment(new FcReportActivity(((RespFcListBean) object).getForumID()));
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_download_photo || index == FcHomeAdapter.Index_download_video) {
            if (object instanceof String) {
                String path = (String) object;
                downloadFileToLocal(path);
                return;
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_like) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model6 = (RespFcListBean) object;
                if (model6.isHasThumb()) {
                    doCancelLikeFc(position, model6);
                    return;
                } else {
                    doLike(position, model6);
                    return;
                }
            }
            return;
        }
        if (index == FcHomeAdapter.Index_click_reply) {
            if (object instanceof RespFcListBean) {
            }
        } else if (index == FcHomeAdapter.Index_click_location && (object instanceof RespFcListBean)) {
            RespFcListBean model7 = (RespFcListBean) object;
            if (!TextUtils.isEmpty(model7.getLocationName()) && model7.getLongitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && model7.getLatitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                FcLocationInfoBean fcLocationInfoBean = new FcLocationInfoBean(model7.getLongitude(), model7.getLatitude(), model7.getLocationName(), model7.getLocationAddress(), model7.getLocationCity());
                FcLocationInfoActivity locationInfoActivity = new FcLocationInfoActivity(fcLocationInfoBean);
                presentFragment(locationInfoActivity);
            }
        }
    }

    public /* synthetic */ void lambda$onAction$2$FcFollowFragment(int position, RespFcListBean model, View dialog) {
        doCancelFollowed(position, model);
    }

    public /* synthetic */ void lambda$onAction$3$FcFollowFragment(int position, RespFcListBean model, View dialog) {
        doDeleteItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$4$FcFollowFragment(int position, RespFcListBean model, View dialog) {
        doIgnoreItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$5$FcFollowFragment(RespFcListBean model, View dialog) {
        ArrayList<FcIgnoreUserBean> list = new ArrayList<>();
        list.add(new FcIgnoreUserBean(model.getCreateBy(), 2));
        doAddIgnoreUser(list);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onPresentFragment(BaseFragment baseFragment) {
        setStopPlayState();
        if (baseFragment != null) {
            presentFragment(baseFragment);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onReplyClick(View v, String receiver, RespFcListBean model, int itemPosition, int replyPosition, boolean isLongClick) {
        if (!isLongClick) {
            if (itemPosition < this.mAdapter.getItemCount()) {
                this.replyItemModel = this.mAdapter.get(itemPosition);
            }
            this.replyParentPosition = itemPosition;
            this.replyChildPosition = replyPosition;
            showReplyFcDialog(receiver, model.getForumID(), model.getCreateBy(), model.isRecommend(), this.replyChildPosition == -1, model.isRecommend(), model.getRequiredVipLevel());
            return;
        }
        showDeleteBottomSheet(model, itemPosition, replyPosition);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.OnFcDoReplyListener
    public void onInputReplyContent(String content, ArrayList<FCEntitysRequest> atUserBeanList) {
        long supID;
        long supUser;
        long replayID;
        long replayUID;
        if (TextUtils.isEmpty(content)) {
            FcToastUtils.show((CharSequence) LocaleController.getString("fc_tips_input_empty_comment", R.string.fc_tips_input_empty_comment));
            return;
        }
        RespFcListBean respFcListBean = this.replyItemModel;
        if (respFcListBean == null) {
            return;
        }
        long forumID = respFcListBean.getForumID();
        long forumUser = this.replyItemModel.getCreateBy();
        if (this.replyChildPosition == -1) {
            supID = 0;
            supUser = 0;
            replayID = forumID;
            replayUID = forumUser;
        } else {
            ArrayList<FcReplyBean> comments = this.replyItemModel.getComments();
            if (comments != null && this.replyChildPosition < comments.size()) {
                FcReplyBean fcReplyBean = comments.get(this.replyChildPosition);
                if (fcReplyBean.getReplayID() == forumID) {
                    long replayID2 = fcReplyBean.getCommentID();
                    long replayUID2 = fcReplyBean.getCreateBy();
                    long supID2 = fcReplyBean.getCommentID();
                    long supUser2 = fcReplyBean.getCreateBy();
                    supID = supID2;
                    supUser = supUser2;
                    replayID = replayID2;
                    replayUID = replayUID2;
                } else {
                    long replayID3 = fcReplyBean.getCommentID();
                    long replayUID3 = fcReplyBean.getCreateBy();
                    long supID3 = fcReplyBean.getSupID();
                    long supUser3 = fcReplyBean.getSupUser();
                    supID = supID3;
                    supUser = supUser3;
                    replayID = replayID3;
                    replayUID = replayUID3;
                }
            } else {
                supID = 0;
                supUser = 0;
                replayID = 0;
                replayUID = 0;
            }
        }
        RequestReplyFcBean mRequestReplyFcBean = new RequestReplyFcBean(forumID, forumUser, replayID, replayUID, supID, supUser, content, this.replyItemModel.getRequiredVipLevel());
        doReplyFc(mRequestReplyFcBean, this.replyParentPosition);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void isActivePlayer(RecyclerView recyclerView) {
        if (this.autoPlayTool == null) {
            this.autoPlayTool = new AutoPlayTool(80, 1);
        }
        if (recyclerView != null) {
            this.autoPlayTool.onActiveWhenNoScrolling(recyclerView);
        }
    }

    private void setStopPlayState() {
        AutoPlayTool autoPlayTool = this.autoPlayTool;
        if (autoPlayTool != null) {
            autoPlayTool.onDeactivate();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doFollowAfterViewChange(int position, boolean isFollow) {
        long createBy = this.mAdapter.get(position).getCreateBy();
        if (this.mAdapter.getItemCount() > 0) {
            this.mAdapter.removeItemByUserID(createBy);
            refreshPageState(false, null);
        }
        deleteLocalItemByUserId(FollowedFcListBean.class, createBy);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doSetItemPermissionAfterViewChange(long forumId, int permission, int position) {
        this.mAdapter.get(position).setPermission(permission);
        updateLocalItemPermissionStatus(FollowedFcListBean.class, forumId, permission);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doLikeAfterViewChange(int position, boolean isLike, FcLikeBean data) {
        View viewByPosition = this.layoutManager.findViewByPosition(position);
        MryTextView btnLike = null;
        if (viewByPosition != null && (btnLike = (MryTextView) viewByPosition.findViewById(R.attr.btn_like)) != null) {
            btnLike.setClickable(true);
        }
        if (data != null) {
            KLog.d("------position" + position + "  " + isLike);
            RespFcListBean model = this.mAdapter.get(position);
            this.mAdapter.get(position).setHasThumb(isLike);
            if (isLike) {
                this.mAdapter.get(position).setThumbUp(model.getThumbUp() + 1);
            } else {
                this.mAdapter.get(position).setThumbUp(this.mAdapter.get(position).getThumbUp() - 1);
            }
            if (btnLike != null) {
                btnLike.setText(model.getThumbUp() > 0 ? String.valueOf(model.getThumbUp()) : "0");
                btnLike.setSelected(isLike);
            }
            updateLocalItemLikeStatus(FollowedFcListBean.class, model.getForumID(), isLike, model.getThumbUp());
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doDeleteItemAfterViewChange(long forumId, int position) {
        this.mAdapter.getDataList().remove(position);
        this.mAdapter.notifyItemRemoved(position);
        FcHomeAdapter fcHomeAdapter = this.mAdapter;
        fcHomeAdapter.notifyItemRangeChanged(position, fcHomeAdapter.getItemCount());
        refreshPageState(false, null);
        deleteLocalItemById(FollowedFcListBean.class, forumId);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doIgnoreItemAfterViewChange(long forumId, int position) {
        this.mAdapter.getDataList().remove(position);
        this.mAdapter.notifyItemRemoved(position);
        FcHomeAdapter fcHomeAdapter = this.mAdapter;
        fcHomeAdapter.notifyItemRangeChanged(position, fcHomeAdapter.getItemCount());
        refreshPageState(false, null);
        deleteLocalItemById(FollowedFcListBean.class, forumId);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doSetIgnoreUserAfterViewChange(boolean isIgnore, ArrayList<FcIgnoreUserBean> ignores) {
        if (isIgnore && ignores != null && ignores.size() > 0) {
            FcIgnoreUserBean ignoreUserBean = ignores.get(0);
            if (ignoreUserBean != null) {
                this.mAdapter.removeItemByUserID(ignoreUserBean.getUserID());
            }
            refreshPageState(false, null);
            deleteLocalItemByUserId(FollowedFcListBean.class, ignores.get(0).getUserID());
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    protected void doReplySuccAfterViewChange(FcReplyBean data, int replyParentPosition) {
        ArrayList<FcReplyBean> morelist = new ArrayList<>();
        morelist.add(data);
        RespFcListBean respFcListBean = this.mAdapter.get(replyParentPosition);
        if (respFcListBean != null) {
            ArrayList<FcReplyBean> comments = respFcListBean.getComments();
            if (comments == null || comments.size() == 0) {
                respFcListBean.setComments(morelist);
            } else {
                comments.addAll(morelist);
            }
            respFcListBean.setCommentCount(respFcListBean.getCommentCount() + 1);
            View viewByPosition = this.layoutManager.findViewByPosition(replyParentPosition);
            if (viewByPosition != null) {
                MryTextView btnReply = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply);
                if (btnReply != null) {
                    btnReply.setText(respFcListBean.getCommentCount() > 0 ? String.valueOf(respFcListBean.getCommentCount()) : "0");
                }
                RecyclerView rvReply = (RecyclerView) viewByPosition.findViewById(R.attr.rv_fc_comm_reply);
                if (rvReply != null) {
                    FcHomeItemReplyAdapter adapter = (FcHomeItemReplyAdapter) rvReply.getAdapter();
                    if (adapter != null && adapter.getItemCount() > 0) {
                        adapter.loadMore(morelist);
                    } else {
                        this.mAdapter.notifyItemChanged(replyParentPosition);
                    }
                }
            }
        }
        updateLocalReplyStatus(FollowedFcListBean.class, data.getForumID(), data);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment
    public void doDeleteReplySuccAfterViewChange(long forumId, long commentId, int parentPosition, int childPosition) {
        FcHomeItemReplyAdapter adapter;
        RespFcListBean respFcListBean = this.mAdapter.get(parentPosition);
        if (respFcListBean != null) {
            View viewByPosition = this.layoutManager.findViewByPosition(parentPosition);
            if (viewByPosition != null) {
                RecyclerView rvReply = (RecyclerView) viewByPosition.findViewById(R.attr.rv_fc_comm_reply);
                if (rvReply != null && childPosition != -1 && (adapter = (FcHomeItemReplyAdapter) rvReply.getAdapter()) != null && adapter.getDataList() != null && childPosition < adapter.getDataList().size()) {
                    FcReplyBean fcReplyBean = adapter.getDataList().get(childPosition);
                    ArrayList<FcReplyBean> temp = new ArrayList<>(adapter.getDataList());
                    Iterator<FcReplyBean> iterator = temp.iterator();
                    while (iterator.hasNext()) {
                        FcReplyBean next = iterator.next();
                        if (next != null && (next.getCommentID() == fcReplyBean.getCommentID() || next.getSupID() == fcReplyBean.getCommentID())) {
                            iterator.remove();
                        }
                    }
                    adapter.refresh(temp);
                    respFcListBean.setCommentCount(temp.size());
                    respFcListBean.getComments().clear();
                    respFcListBean.getComments().addAll(temp);
                }
                MryTextView btnReply = (MryTextView) viewByPosition.findViewById(R.attr.btn_reply);
                if (btnReply != null) {
                    btnReply.setText(respFcListBean.getCommentCount() > 0 ? String.valueOf(respFcListBean.getCommentCount()) : "0");
                }
            }
            if (respFcListBean != null) {
                int commentCount = respFcListBean.getCommentCount();
                deleteLocalReply(FollowedFcListBean.class, forumId, commentId, commentCount);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcFragment, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
    }
}
