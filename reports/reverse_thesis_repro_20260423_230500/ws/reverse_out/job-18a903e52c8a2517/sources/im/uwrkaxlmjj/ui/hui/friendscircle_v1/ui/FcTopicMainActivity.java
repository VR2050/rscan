package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcPageMinePresenter;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.google.gson.Gson;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.fc.FcLocationInfoBean;
import im.uwrkaxlmjj.javaBean.fc.PublishFcBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcHomeItemReplyAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.UserFcListAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration.SpacesItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.state.ScreenViewState;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.AutoPlayTool;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcTopicMainActivity extends CommFcListActivity implements NotificationCenter.NotificationCenterDelegate, FcItemActionClickListener, BaseFcContract.IFcPageMineView {
    private AppBarLayout appBarLayout;
    private AutoPlayTool autoPlayTool;
    private MryRoundButton btnFollow;
    private MryEmptyView emptyView;
    private ImagePreSelectorActivity imageSelectorAlert;
    private ImageView ivActionBarBg;
    private ImageView ivBack;
    private ImageView ivCamera;
    private UserFcListAdapter mAdapter;
    private FcPageMinePresenter mPresenter;
    private SmartRefreshLayout refreshLayout;
    private RespFcListBean replyItemModel;
    private RecyclerListView rv;
    private FrameLayout rvContainer;
    private MryTextView tvScanCount;
    private MryTextView tvTopicDes;
    private MryTextView tvTopicName;
    private String TAG = FcTopicMainActivity.class.getSimpleName();
    private int pageNo = 0;
    private int replyParentPosition = -1;
    private int replyChildPosition = -1;
    RecyclerView.OnScrollListener rvScrollListener = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity.3
        boolean isScroll = false;

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            super.onScrolled(recyclerView, dx, dy);
            if (FcTopicMainActivity.this.autoPlayTool != null && this.isScroll) {
                FcTopicMainActivity.this.autoPlayTool.onScrolledAndDeactivate();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            super.onScrollStateChanged(recyclerView, newState);
            this.isScroll = newState != 0;
            if (newState == 0) {
                if (FcTopicMainActivity.this.refreshLayout.getState() == RefreshState.None || FcTopicMainActivity.this.refreshLayout.getState() == RefreshState.RefreshFinish) {
                    FcTopicMainActivity.this.isActivePlayer(recyclerView);
                }
            }
        }
    };
    private ArrayList<MediaController.PhotoEntry> photoEntries = new ArrayList<>();

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_fc_topic_main;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        this.actionBar.setAddToContainer(false);
        this.refreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.refreshLayout);
        this.appBarLayout = (AppBarLayout) this.fragmentView.findViewById(R.attr.appBarLayout);
        CollapsingToolbarLayout collapsingToolbarLayout = (CollapsingToolbarLayout) this.fragmentView.findViewById(R.attr.collapsingToolbarLayout);
        this.ivBack = (ImageView) this.fragmentView.findViewById(R.attr.ivBack);
        this.ivCamera = (ImageView) this.fragmentView.findViewById(R.attr.ivCamera);
        final FrameLayout actionBarContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.actionBarContainer);
        this.ivActionBarBg = (ImageView) this.fragmentView.findViewById(R.attr.ivActionBarBg);
        this.tvTopicName = (MryTextView) this.fragmentView.findViewById(R.attr.tvTopicName);
        this.tvScanCount = (MryTextView) this.fragmentView.findViewById(R.attr.tvScanCount);
        this.tvTopicDes = (MryTextView) this.fragmentView.findViewById(R.attr.tvTopicDes);
        this.btnFollow = (MryRoundButton) this.fragmentView.findViewById(R.attr.btnFollow);
        this.rvContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.rvContainer);
        this.rv = (RecyclerListView) this.fragmentView.findViewById(R.attr.rv);
        this.appBarLayout.addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$N6poJyFFnKYuwok3FsmaJdEXsg8
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public final void onOffsetChanged(AppBarLayout appBarLayout, int i) {
                this.f$0.lambda$initView$0$FcTopicMainActivity(actionBarContainer, appBarLayout, i);
            }
        });
        collapsingToolbarLayout.setMinimumHeight(AndroidUtilities.statusBarHeight + ActionBar.getCurrentActionBarHeight());
        actionBarContainer.setPadding(0, AndroidUtilities.statusBarHeight, 0, 0);
        this.ivBack.setBackground(Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(42.0f), 0, Theme.getColor(Theme.key_actionBarDefaultSelector)));
        this.ivBack.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$zKgH2AFWyCJnIIERXTrwPoxE_fw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$1$FcTopicMainActivity(view);
            }
        });
        this.ivCamera.setBackground(Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(42.0f), 0, Theme.getColor(Theme.key_actionBarDefaultSelector)));
        this.ivCamera.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$80QEXZ5LrlmLhzNFTu9FqkNzltw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FcTopicMainActivity.lambda$initView$2(view);
            }
        });
        this.btnFollow.setPrimaryRadiusAdjustBoundsFillStyle();
        this.btnFollow.setBackgroundColor(-13709571);
        this.refreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity.1
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                FcTopicMainActivity.this.loadFcBaseInfo();
                FcTopicMainActivity.this.pageNo = 0;
                FcTopicMainActivity.this.getFcPageList();
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                FcTopicMainActivity.this.getFcPageList();
            }
        });
        this.rv.addItemDecoration(new SpacesItemDecoration(AndroidUtilities.dp(7.0f)));
        this.rv.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        UserFcListAdapter userFcListAdapter = new UserFcListAdapter(new ArrayList(), getParentActivity(), getClassGuid(), this);
        this.mAdapter = userFcListAdapter;
        userFcListAdapter.setFooterCount(1);
        this.rv.setAdapter(this.mAdapter);
        MryEmptyView mryEmptyView = new MryEmptyView(getParentActivity());
        this.emptyView = mryEmptyView;
        mryEmptyView.attach(this.rvContainer);
        this.emptyView.showLoading();
    }

    public /* synthetic */ void lambda$initView$0$FcTopicMainActivity(FrameLayout actionBarContainer, AppBarLayout appBarLayout, int i) {
        float offset = Math.abs(i) / appBarLayout.getTotalScrollRange();
        if (offset <= 0.0f) {
            actionBarContainer.setBackgroundColor(0);
            this.ivBack.clearColorFilter();
            this.ivCamera.clearColorFilter();
        } else if (offset >= 1.0f) {
            actionBarContainer.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
            this.ivBack.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
            this.ivCamera.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
        } else {
            actionBarContainer.setBackgroundColor(AndroidUtilities.alphaColor(offset, Theme.getColor(Theme.key_actionBarDefault)));
            this.ivBack.setColorFilter(new PorterDuffColorFilter(AndroidUtilities.alphaColor(offset, Theme.getColor(Theme.key_actionBarDefaultIcon)), PorterDuff.Mode.MULTIPLY));
            this.ivCamera.setColorFilter(new PorterDuffColorFilter(AndroidUtilities.alphaColor(offset, Theme.getColor(Theme.key_actionBarDefaultIcon)), PorterDuff.Mode.MULTIPLY));
        }
    }

    public /* synthetic */ void lambda$initView$1$FcTopicMainActivity(View v) {
        finishFragment();
    }

    static /* synthetic */ void lambda$initView$2(View v) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getParentActivity().getWindow().setSoftInputMode(16);
        VideoPlayerManager.getInstance().resume();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$YaL0TnZWiG3LTSiaurXhMwwU-OA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onResume$3$FcTopicMainActivity();
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$onResume$3$FcTopicMainActivity() {
        RecyclerView.OnScrollListener onScrollListener = this.rvScrollListener;
        if (onScrollListener != null) {
            onScrollListener.onScrollStateChanged(this.rv, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        if (ScreenViewState.isFullScreen(VideoPlayerManager.getInstance().getmScreenState())) {
            VideoPlayerManager.getInstance().onBackPressed();
        }
        setStopPlayState();
        super.onPause();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcIgnoreOrDeleteItem);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcIgnoreUser);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcDeleteReplyItem);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fcPublishSuccess);
        VideoPlayerManager.getInstance().release();
        FcPageMinePresenter fcPageMinePresenter = this.mPresenter;
        if (fcPageMinePresenter != null) {
            fcPageMinePresenter.unSubscribeTask();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcFollowStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcPermissionStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcIgnoreOrDeleteItem);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcLikeStatusUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcIgnoreUser);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcReplyItem);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcDeleteReplyItem);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fcPublishSuccess);
        this.mPresenter = new FcPageMinePresenter(this);
        loadFcBackground(getUserConfig().getClientUserId());
        loadUserInfo();
        loadFcBaseInfo();
        getFcPageList();
    }

    private void loadUserInfo() {
        if (getUserConfig() != null) {
            getUserConfig().getClientUserId();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void setFcBackground(String path) {
        super.setFcBackground(path);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadFcBaseInfo() {
        this.mPresenter.getActionCount(getUserConfig().getClientUserId());
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineView
    public void getActionCountSucc(RespFcUserStatisticsBean data) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getFcPageList() {
        long forumId = this.pageNo == 0 ? 0L : this.mAdapter.getEndListId();
        this.mPresenter.getFCList(20, forumId);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineView
    public void getFCListSucc(ArrayList<RespFcListBean> data) {
        this.refreshLayout.finishRefresh();
        this.refreshLayout.finishLoadMore();
        setData(data);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineView
    public void getFCListFailed(String msg) {
        this.refreshLayout.finishRefresh();
        this.refreshLayout.finishLoadMore();
        FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail));
    }

    private void setData(ArrayList<RespFcListBean> mFclistBeanList) {
        if (this.pageNo == 0) {
            if (mFclistBeanList == null || mFclistBeanList.size() == 0) {
                this.refreshLayout.setEnableLoadMore(false);
                this.mAdapter.refresh(new ArrayList());
            } else {
                if (mFclistBeanList.size() < 20) {
                    this.refreshLayout.setEnableLoadMore(false);
                    mFclistBeanList.add(new RespFcListBean());
                } else {
                    this.refreshLayout.setEnableLoadMore(true);
                }
                this.mAdapter.refresh(mFclistBeanList);
                this.pageNo++;
            }
            AutoPlayTool autoPlayTool = this.autoPlayTool;
            if (autoPlayTool != null) {
                autoPlayTool.onRefreshDeactivate();
            }
            refreshPageState();
            return;
        }
        if (mFclistBeanList == null || mFclistBeanList.size() < 20) {
            mFclistBeanList.add(new RespFcListBean());
            this.refreshLayout.setEnableLoadMore(false);
        }
        this.mAdapter.loadMore(mFclistBeanList);
        refreshPageState();
        if (mFclistBeanList.size() > 0) {
            this.pageNo++;
        }
    }

    private void refreshPageState() {
        UserFcListAdapter userFcListAdapter = this.mAdapter;
        if (userFcListAdapter != null && userFcListAdapter.getDataList().size() <= this.mAdapter.getHeaderFooterCount()) {
            this.emptyView.showEmpty();
        } else {
            this.emptyView.showContent();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        RespFcListBean respFcListBean;
        int i1;
        int childPosition;
        if (id == NotificationCenter.userFullInfoDidLoad) {
            if (args != null && args.length >= 2 && (args[1] instanceof TLRPC.UserFull)) {
                Integer uid = (Integer) args[0];
                if (uid.intValue() == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                    TLRPC.UserFull userInfo = (TLRPC.UserFull) args[1];
                    boolean z = userInfo instanceof TLRPCContacts.CL_userFull_v1;
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcFollowStatusUpdate) {
            String tag = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag)) {
                long createBy = ((Long) args[1]).longValue();
                boolean isFollow = ((Boolean) args[2]).booleanValue();
                int position = -1;
                UserFcListAdapter userFcListAdapter = this.mAdapter;
                if (userFcListAdapter != null) {
                    List<RespFcListBean> dataList = userFcListAdapter.getDataList();
                    int i = 0;
                    while (true) {
                        if (i >= dataList.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean2 = dataList.get(i);
                        if (respFcListBean2 == null || respFcListBean2.getCreateBy() != createBy) {
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
                UserFcListAdapter userFcListAdapter2 = this.mAdapter;
                if (userFcListAdapter2 != null) {
                    List<RespFcListBean> dataList2 = userFcListAdapter2.getDataList();
                    int i2 = 0;
                    while (true) {
                        if (i2 >= dataList2.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean3 = dataList2.get(i2);
                        if (respFcListBean3 == null || respFcListBean3.getForumID() != forumId) {
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
                UserFcListAdapter userFcListAdapter3 = this.mAdapter;
                if (userFcListAdapter3 != null && forumId2 > 0) {
                    List<RespFcListBean> dataList3 = userFcListAdapter3.getDataList();
                    int i3 = 0;
                    while (true) {
                        if (i3 >= dataList3.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean4 = dataList3.get(i3);
                        if (respFcListBean4 == null || respFcListBean4.getForumID() != forumId2) {
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
                        RespFcListBean respFcListBean5 = dataList4.get(i4);
                        if (respFcListBean5 == null || respFcListBean5.getForumID() != fcLikeBean.getForumID()) {
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
                        RespFcListBean respFcListBean6 = dataList5.get(i5);
                        if (respFcListBean6 == null || respFcListBean6.getCreateBy() != ignores.get(0).getUserID()) {
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
                UserFcListAdapter userFcListAdapter4 = this.mAdapter;
                if (userFcListAdapter4 != null && data != null) {
                    List<RespFcListBean> dataList6 = userFcListAdapter4.getDataList();
                    int i6 = 0;
                    while (true) {
                        if (i6 >= dataList6.size()) {
                            break;
                        }
                        RespFcListBean respFcListBean7 = dataList6.get(i6);
                        if (respFcListBean7 == null || respFcListBean7.getForumID() != data.getForumID()) {
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
                UserFcListAdapter userFcListAdapter5 = this.mAdapter;
                if (userFcListAdapter5 != null && forumId3 > 0 && commentId > 0) {
                    List<RespFcListBean> dataList7 = userFcListAdapter5.getDataList();
                    for (int i7 = 0; i7 < dataList7.size(); i7++) {
                        RespFcListBean respFcListBean8 = dataList7.get(i7);
                        if (respFcListBean8 != null && respFcListBean8.getForumID() == forumId3) {
                            int parentPosition = i7;
                            ArrayList<FcReplyBean> comments = respFcListBean8.getComments();
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
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fcPublishSuccess) {
            String tag8 = (String) args[0];
            if (!TextUtils.equals(this.TAG, tag8) && (respFcListBean = (RespFcListBean) args[1]) != null) {
                doAfterPublishSuccess(respFcListBean);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void didSelectOnePhoto(String photosPath) {
        super.didSelectOnePhoto(photosPath);
        if (!TextUtils.isEmpty(photosPath)) {
            uploadFile(photosPath, new DataListener<BResponse<FcMediaResponseBean>>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity.2
                @Override // com.bjz.comm.net.base.DataListener
                public void onResponse(BResponse<FcMediaResponseBean> result) {
                    if (result != null && result.Data != null) {
                        String name = result.Data.getName();
                        if (!TextUtils.isEmpty(name)) {
                            FcTopicMainActivity.this.mPresenter.setFcBackground(name);
                        }
                    }
                }

                @Override // com.bjz.comm.net.base.DataListener
                public void onError(Throwable throwable) {
                    FcToastUtils.show((CharSequence) "设置失败");
                }
            });
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineView
    public void setFcBackgroundSucc(String servicePath, String msg) {
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineView
    public void setFcBackgroundFailed(String msg) {
        FcToastUtils.show((CharSequence) msg);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onAction(View view, int index, final int position, Object object) {
        if (index == UserFcListAdapter.Index_click_avatar) {
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
        if (index == UserFcListAdapter.Index_click_follow) {
            if (object instanceof RespFcListBean) {
                doFollow(position, (RespFcListBean) object);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_cancel_follow) {
            if (object instanceof RespFcListBean) {
                doCancelFollowed(position, (RespFcListBean) object);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_public) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 1, position);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_private) {
            if (object instanceof RespFcListBean) {
                setFcItemPermission((RespFcListBean) object, 2, position);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_delete) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model2 = (RespFcListBean) object;
                FcDialogUtil.chooseIsDeleteMineItemDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$1B6k0sIZhVKMRJzKh8EZBZ8gYME
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$4$FcTopicMainActivity(position, model2, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_shield_item) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model3 = (RespFcListBean) object;
                FcDialogUtil.chooseIsSetOtherFcItemPrivacyDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$TGe7jhmkzxMn7Y2kIusNXuVK41o
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$5$FcTopicMainActivity(position, model3, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_shield_user) {
            if (object instanceof RespFcListBean) {
                final RespFcListBean model4 = (RespFcListBean) object;
                FcDialogUtil.choosePrivacyAllFcDialog(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcTopicMainActivity$6MN79O5hVRSR9gC4sZJ8g_EDnuw
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onAction$6$FcTopicMainActivity(model4, view2);
                    }
                }, null);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_pop_report) {
            if (object instanceof RespFcListBean) {
                presentFragment(new FcReportActivity(((RespFcListBean) object).getForumID()));
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_download_photo || index == UserFcListAdapter.Index_download_video) {
            if (object instanceof String) {
                String path = (String) object;
                downloadFileToLocal(path);
                return;
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_like) {
            if (object instanceof RespFcListBean) {
                RespFcListBean model5 = (RespFcListBean) object;
                if (model5.isHasThumb()) {
                    doCancelLikeFc(model5.getForumID(), model5.getCreateBy(), -1L, -1L, position);
                    return;
                } else {
                    doLike(model5.getForumID(), model5.getCreateBy(), -1L, -1L, position);
                    return;
                }
            }
            return;
        }
        if (index == UserFcListAdapter.Index_click_reply) {
            if (object instanceof RespFcListBean) {
            }
        } else if (index == UserFcListAdapter.Index_click_location && (object instanceof RespFcListBean)) {
            RespFcListBean model6 = (RespFcListBean) object;
            if (!TextUtils.isEmpty(model6.getLocationName()) && model6.getLongitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE && model6.getLatitude() != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                FcLocationInfoBean fcLocationInfoBean = new FcLocationInfoBean(model6.getLongitude(), model6.getLatitude(), model6.getLocationName(), model6.getLocationAddress(), model6.getLocationCity());
                FcLocationInfoActivity locationInfoActivity = new FcLocationInfoActivity(fcLocationInfoBean);
                presentFragment(locationInfoActivity);
            }
        }
    }

    public /* synthetic */ void lambda$onAction$4$FcTopicMainActivity(int position, RespFcListBean model, View dialog) {
        doDeleteItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$5$FcTopicMainActivity(int position, RespFcListBean model, View dialog) {
        doIgnoreItem(position, model);
    }

    public /* synthetic */ void lambda$onAction$6$FcTopicMainActivity(RespFcListBean model, View dialog) {
        ArrayList<FcIgnoreUserBean> list = new ArrayList<>();
        list.add(new FcIgnoreUserBean(model.getCreateBy(), 2));
        doAddIgnoreUser(list);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onReplyClick(View v, String receiver, RespFcListBean model, int itemPosition, int replyPosition, boolean isLongClick) {
        if (!isLongClick) {
            if (itemPosition < this.mAdapter.getItemCount()) {
                this.replyItemModel = this.mAdapter.get(itemPosition);
            }
            this.replyParentPosition = itemPosition;
            this.replyChildPosition = replyPosition;
            showReplyFcDialog(receiver, this.replyItemModel.getForumID(), model.getCreateBy(), false, this.replyChildPosition == -1, model.isRecommend(), model.getRequiredVipLevel());
            return;
        }
        showDeleteBottomSheet(model, itemPosition, replyPosition);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener
    public void onPresentFragment(BaseFragment baseFragment) {
        setStopPlayState();
        if (baseFragment != null) {
            presentFragment(baseFragment);
        }
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

    public void doAfterPublishSuccess(RespFcListBean mResponseFcPublishBackBean) {
        KLog.d("----------mResponseFcPublishBackBean" + mResponseFcPublishBackBean);
        UserFcListAdapter userFcListAdapter = this.mAdapter;
        if (userFcListAdapter != null && userFcListAdapter.getDataList().size() > 0) {
            this.mAdapter.getDataList().add(0, mResponseFcPublishBackBean);
            this.mAdapter.notifyItemInserted(0);
            UserFcListAdapter userFcListAdapter2 = this.mAdapter;
            userFcListAdapter2.notifyItemRangeChanged(0, userFcListAdapter2.getCount());
        } else {
            ArrayList<RespFcListBean> dataList = new ArrayList<>();
            dataList.add(mResponseFcPublishBackBean);
            dataList.add(new RespFcListBean());
            this.mAdapter.refresh(dataList);
        }
        refreshPageState();
        this.rv.scrollToPosition(0);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doFollowAfterViewChange(int position, boolean isFollow) {
        MryTextView btnFollow;
        long createBy = this.mAdapter.get(position).getCreateBy();
        if (this.mAdapter.getItemCount() > 0) {
            int startIndex = this.mAdapter.getHeaderCount();
            for (int j = startIndex; j < this.mAdapter.getCount(); j++) {
                if (this.mAdapter.get(j).getCreateBy() == createBy) {
                    this.mAdapter.getDataList().get(j).setHasFollow(isFollow);
                    View viewByPosition = this.layoutManager.findViewByPosition(j);
                    if (viewByPosition != null && (btnFollow = (MryTextView) viewByPosition.findViewById(R.attr.btn_follow)) != null && btnFollow.getVisibility() == 0) {
                        btnFollow.setText(isFollow ? "已关注" : "关注");
                        btnFollow.setSelected(isFollow);
                    }
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doSetItemPermissionAfterViewChange(long forumId, int permission, int position) {
        this.mAdapter.get(position).setPermission(permission);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
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
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doDeleteItemAfterViewChange(long forumId, int position) {
        this.mAdapter.getDataList().remove(position);
        this.mAdapter.notifyItemRemoved(position);
        UserFcListAdapter userFcListAdapter = this.mAdapter;
        userFcListAdapter.notifyItemRangeChanged(position, userFcListAdapter.getItemCount());
        refreshPageState();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doIgnoreItemAfterViewChange(long forumId, int position) {
        this.mAdapter.getDataList().remove(position);
        this.mAdapter.notifyItemRemoved(position);
        UserFcListAdapter userFcListAdapter = this.mAdapter;
        userFcListAdapter.notifyItemRangeChanged(position, userFcListAdapter.getItemCount());
        refreshPageState();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doSetIgnoreUserAfterViewChange(boolean isIgnore, ArrayList<FcIgnoreUserBean> ignores) {
        FcIgnoreUserBean ignoreUserBean;
        if (isIgnore && ignores != null && ignores.size() > 0 && (ignoreUserBean = ignores.get(0)) != null) {
            this.mAdapter.removeItemByUserID(ignoreUserBean.getUserID());
        }
        refreshPageState();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doReplySuccAfterViewChange(FcReplyBean data, int replyParentPosition) {
        RespFcListBean respFcListBean = this.mAdapter.get(replyParentPosition);
        if (respFcListBean != null && data != null) {
            ArrayList<FcReplyBean> comments = respFcListBean.getComments();
            ArrayList<FcReplyBean> morelist = new ArrayList<>();
            morelist.add(data);
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
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    public void doDeleteReplySuccAfterViewChange(long forumId, long commentId, int parentPosition, int childPosition) {
        View viewByPosition;
        FcHomeItemReplyAdapter adapter;
        RespFcListBean respFcListBean = this.mAdapter.get(parentPosition);
        if (respFcListBean != null && (viewByPosition = this.layoutManager.findViewByPosition(parentPosition)) != null) {
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
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
        FcToastUtils.show((CharSequence) (msg == null ? LocaleController.getString("friendscircle_home_request_fail", R.string.friendscircle_home_request_fail) : msg));
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

    public void startPublishActivity() {
        String publishJson = AppPreferenceUtil.getString("PublishFcBean", "");
        if (!TextUtils.isEmpty(publishJson)) {
            PublishFcBean publishFcBean = (PublishFcBean) new Gson().fromJson(publishJson, PublishFcBean.class);
            if (publishFcBean != null) {
                presentFragment(new FcPublishActivity(publishFcBean));
                AppPreferenceUtil.putString("PublishFcBean", "");
                return;
            } else {
                openAttachMenu();
                return;
            }
        }
        openAttachMenu();
    }

    private void openAttachMenu() {
        createChatAttachView();
        this.imageSelectorAlert.setCurrentSelectMediaType(0);
        this.imageSelectorAlert.loadGalleryPhotos();
        this.imageSelectorAlert.setMaxSelectedPhotos(9, true);
        this.imageSelectorAlert.init();
        this.imageSelectorAlert.setCancelable(false);
        showDialog(this.imageSelectorAlert);
    }

    private void createChatAttachView() {
        if (this.imageSelectorAlert == null) {
            ImagePreSelectorActivity imagePreSelectorActivity = new ImagePreSelectorActivity(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity.4
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity, im.uwrkaxlmjj.ui.actionbar.BottomSheet
                public void dismissInternal() {
                    if (FcTopicMainActivity.this.imageSelectorAlert.isShowing()) {
                        AndroidUtilities.requestAdjustResize(FcTopicMainActivity.this.getParentActivity(), FcTopicMainActivity.this.classGuid);
                        for (int i = 0; i < FcTopicMainActivity.this.photoEntries.size(); i++) {
                            if (((MediaController.PhotoEntry) FcTopicMainActivity.this.photoEntries.get(i)).isVideo) {
                                super.dismissInternal();
                                return;
                            }
                        }
                    }
                    super.dismissInternal();
                }
            };
            this.imageSelectorAlert = imagePreSelectorActivity;
            imagePreSelectorActivity.setDelegate(new ImagePreSelectorActivity.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcTopicMainActivity.5
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (button != 8 && button != 7 && (button != 4 || FcTopicMainActivity.this.imageSelectorAlert.getSelectedPhotos().isEmpty())) {
                        if (FcTopicMainActivity.this.imageSelectorAlert != null) {
                            FcTopicMainActivity.this.imageSelectorAlert.dismissWithButtonClick(button);
                            FcTopicMainActivity.this.presentFragment(new FcPublishActivity());
                            return;
                        }
                        return;
                    }
                    if (button != 8) {
                        FcTopicMainActivity.this.imageSelectorAlert.dismiss();
                    }
                    HashMap<Object, Object> selectedPhotos = FcTopicMainActivity.this.imageSelectorAlert.getSelectedPhotos();
                    ArrayList<Object> selectedPhotosOrder = FcTopicMainActivity.this.imageSelectorAlert.getSelectedPhotosOrder();
                    int currentSelectMediaType = FcTopicMainActivity.this.imageSelectorAlert.getCurrentSelectMediaType();
                    if (!selectedPhotos.isEmpty() && !selectedPhotosOrder.isEmpty()) {
                        FcTopicMainActivity.this.presentFragment(new FcPublishActivity(FcTopicMainActivity.this.imageSelectorAlert, selectedPhotos, selectedPhotosOrder, currentSelectMediaType));
                    } else {
                        FcTopicMainActivity.this.presentFragment(new FcPublishActivity());
                    }
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void didSelectBot(TLRPC.User user) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void onCameraOpened() {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public View getRevealView() {
                    return null;
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void needEnterComment() {
                    AndroidUtilities.setAdjustResizeToNothing(FcTopicMainActivity.this.getParentActivity(), FcTopicMainActivity.this.classGuid);
                }
            });
        }
    }
}
