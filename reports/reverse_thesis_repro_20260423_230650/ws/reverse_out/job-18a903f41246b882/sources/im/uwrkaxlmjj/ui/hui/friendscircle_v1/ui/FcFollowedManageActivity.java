package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.ResponseFcAttentionUsertBeanV1;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.utils.JsonCreateUtils;
import com.bjz.comm.net.utils.RxHelper;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.decoration.TopDecorationWithSearch;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.RequestBody;

/* JADX INFO: loaded from: classes5.dex */
public class FcFollowedManageActivity extends CommFcActivity {
    private String TAG = getClass().getSimpleName();
    public ArrayList<Integer> canceledFocusUser = new ArrayList<>();
    private FrameLayout container;
    private FrameLayout fl_search_container;
    private FrameLayout fl_search_cover;
    private RecyclerListView listView;
    private MyAdapter myAdapter;
    private MysearchAdapter mysearchAdapter;
    private String searchText;
    private MrySearchView searchView;
    private boolean searchWas;
    private boolean searching;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_fc_followed_manage;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        initActionBar();
        initSearchView();
        initListView();
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("manage", R.string.manage));
        this.actionBar.setDelegate(new ActionBar.ActionBarDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$33laznyJ6boi_TZ07KClV-UP--4
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarDelegate
            public final void onSearchFieldVisibilityChanged(boolean z) {
                this.f$0.lambda$initActionBar$0$FcFollowedManageActivity(z);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcFollowedManageActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FcFollowedManageActivity.this.finishFragment();
                }
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$0$FcFollowedManageActivity(boolean visible) {
        this.actionBar.getBackButton().setVisibility(visible ? 0 : 8);
    }

    private void initListView() {
        this.container = (FrameLayout) this.fragmentView.findViewById(R.attr.container);
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listView);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(this.mContext));
        this.listView.addItemDecoration(new TopDecorationWithSearch(60, false));
        this.mysearchAdapter = new MysearchAdapter(this.mContext);
        RecyclerListView recyclerListView2 = this.listView;
        MyAdapter myAdapter = new MyAdapter(this.mContext);
        this.myAdapter = myAdapter;
        recyclerListView2.setAdapter(myAdapter);
        this.myAdapter.emptyAttachView(this.container);
        MryEmptyView emptyView = this.myAdapter.getEmptyView();
        emptyView.setEmptyText(LocaleController.getString(R.string.NoFollowedPageDataMessages));
        emptyView.setEmptyResId(R.id.img_empty_default);
        emptyView.setErrorResId(R.id.img_empty_default);
        emptyView.getTextView().setTextColor(this.mContext.getResources().getColor(R.color.color_FFDBC9B8));
        emptyView.getBtn().setPrimaryRadiusAdjustBoundsFillStyle();
        emptyView.getBtn().setRoundBgGradientColors(new int[]{-4789508, -13187843});
        emptyView.getBtn().setStrokeWidth(0);
        emptyView.getBtn().setPadding(AndroidUtilities.dp(15.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(15.0f), AndroidUtilities.dp(5.0f));
        emptyView.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$41CoHKdffDdce3TYfDBakbctRYU
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initListView$1$FcFollowedManageActivity(z);
            }
        });
        this.myAdapter.setStartPage(0);
        this.myAdapter.showLoading();
        this.listView.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcFollowedManageActivity.2
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    if (FcFollowedManageActivity.this.searching && FcFollowedManageActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(FcFollowedManageActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                int off = recyclerView.computeVerticalScrollOffset();
                if (off == 0) {
                    FcFollowedManageActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
                    FcFollowedManageActivity.this.fl_search_container.setScrollY(off > AndroidUtilities.dp(55.0f) ? AndroidUtilities.dp(55.0f) : off);
                } else if (off > 0) {
                    FcFollowedManageActivity.this.fl_search_container.setBackgroundColor(0);
                    FcFollowedManageActivity.this.fl_search_container.setScrollY(off > AndroidUtilities.dp(55.0f) ? AndroidUtilities.dp(55.0f) : off);
                }
            }
        });
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcFollowedManageActivity.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                TextView tv_attention = (TextView) view.findViewById(R.attr.tv_attention);
                FcUserInfoBean fcUserInfoBean = FcFollowedManageActivity.this.searchWas ? FcFollowedManageActivity.this.mysearchAdapter.getData().get(position) : FcFollowedManageActivity.this.myAdapter.getData().get(position);
                if (!tv_attention.isSelected()) {
                    FcFollowedManageActivity.this.doFollow(position, fcUserInfoBean);
                } else {
                    FcFollowedManageActivity.this.doCancelFocusUser(position, fcUserInfoBean);
                }
            }
        });
    }

    public /* synthetic */ boolean lambda$initListView$1$FcFollowedManageActivity(boolean isEmptyButton) {
        this.myAdapter.showLoading();
        getFcPageList(0, "");
        return false;
    }

    private void initSearchView() {
        FrameLayout frameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_search_cover);
        this.fl_search_cover = frameLayout;
        frameLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$EmNaUHM0uuPHYU3jsFIy2PDo4-U
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FcFollowedManageActivity.lambda$initSearchView$2(view);
            }
        });
        FrameLayout frameLayout2 = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_search_container);
        this.fl_search_container = frameLayout2;
        frameLayout2.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
        MrySearchView mrySearchView = (MrySearchView) this.fragmentView.findViewById(R.attr.searchview);
        this.searchView = mrySearchView;
        mrySearchView.setCancelTextColor(this.mContext.getResources().getColor(R.color.color_778591));
        this.searchView.setEditTextBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), Theme.getColor(Theme.key_divider), AndroidUtilities.dp(50.0f)));
        this.searchView.setHintText(LocaleController.getString("searchAttentionUser", R.string.searchAttentionUser));
        this.searchView.setiSearchViewDelegate(new MrySearchView.ISearchViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcFollowedManageActivity.4
            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onStart(boolean focus) {
                if (focus) {
                    FcFollowedManageActivity fcFollowedManageActivity = FcFollowedManageActivity.this;
                    fcFollowedManageActivity.hideTitle(fcFollowedManageActivity.fragmentView);
                    FcFollowedManageActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    FcFollowedManageActivity.this.fl_search_cover.setVisibility(0);
                    return;
                }
                FcFollowedManageActivity fcFollowedManageActivity2 = FcFollowedManageActivity.this;
                fcFollowedManageActivity2.showTitle(fcFollowedManageActivity2.fragmentView);
                FcFollowedManageActivity.this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
                FcFollowedManageActivity.this.fl_search_cover.setVisibility(8);
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchExpand() {
                FcFollowedManageActivity.this.searching = true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public boolean canCollapseSearch() {
                FcFollowedManageActivity.this.searching = false;
                FcFollowedManageActivity.this.searchWas = false;
                FcFollowedManageActivity.this.listView.setAdapter(FcFollowedManageActivity.this.myAdapter);
                FcFollowedManageActivity.this.myAdapter.notifyDataSetChanged();
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchCollapse() {
                FcFollowedManageActivity.this.searching = false;
                FcFollowedManageActivity.this.searchWas = false;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onTextChange(String text) {
                if (FcFollowedManageActivity.this.mysearchAdapter != null) {
                    FcFollowedManageActivity.this.searchText = text;
                    FcFollowedManageActivity.this.searchWas = true;
                    if (text.length() != 0) {
                        if (FcFollowedManageActivity.this.listView != null) {
                            FcFollowedManageActivity.this.listView.setAdapter(FcFollowedManageActivity.this.mysearchAdapter);
                            FcFollowedManageActivity.this.mysearchAdapter.notifyDataSetChanged();
                        }
                        FcFollowedManageActivity.this.getFcPageList(0, text);
                        return;
                    }
                    if (FcFollowedManageActivity.this.searching) {
                        FcFollowedManageActivity.this.listView.setAdapter(FcFollowedManageActivity.this.mysearchAdapter);
                        FcFollowedManageActivity.this.mysearchAdapter.getData().clear();
                        FcFollowedManageActivity.this.mysearchAdapter.notifyDataSetChanged();
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onActionSearch(String trim) {
            }
        });
    }

    static /* synthetic */ void lambda$initSearchView$2(View v) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        getFcPageList(0, "");
    }

    private class MysearchAdapter extends PageSelectionAdapter<FcUserInfoBean, PageHolder> {
        public MysearchAdapter(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(FcFollowedManageActivity.this.mContext).inflate(R.layout.item_attention_manage, parent, false);
            return new PageHolder(view, 0);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, FcUserInfoBean item) {
            BackupImageView img_avatar = (BackupImageView) holder.itemView.findViewById(R.attr.img_avatar);
            TextView tv_nick_name = (TextView) holder.itemView.findViewById(R.attr.tv_nick_name);
            TextView tv_gender_age = (TextView) holder.itemView.findViewById(R.attr.tv_gender_age);
            TextView tv_attention = (TextView) holder.itemView.findViewById(R.attr.tv_attention);
            if (Theme.getCurrentTheme().isLight()) {
                tv_nick_name.setTextColor(FcFollowedManageActivity.this.mContext.getResources().getColor(R.color.color_111111));
            } else {
                tv_nick_name.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            }
            tv_nick_name.setText(StringUtils.handleTextName(ContactsController.formatName(item.getFirstName(), item.getLastName()), 12));
            img_avatar.setRoundRadius(AndroidUtilities.dp(5.0f));
            AvatarPhotoBean avatarPhotoBean = item.getPhoto();
            if (avatarPhotoBean != null) {
                int photoSize = avatarPhotoBean.getSmallPhotoSize();
                int localId = avatarPhotoBean.getSmallLocalId();
                long volumeId = avatarPhotoBean.getSmallVolumeId();
                if (photoSize != 0 && volumeId != 0 && avatarPhotoBean.getAccess_hash() != 0) {
                    TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                    inputPeer.user_id = item.getUserId();
                    inputPeer.access_hash = item.getAccessHash();
                    ImageLocation imageLocation = new ImageLocation();
                    imageLocation.dc_id = 2;
                    imageLocation.photoPeer = inputPeer;
                    imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                    imageLocation.location.local_id = localId;
                    imageLocation.location.volume_id = volumeId;
                    AvatarDrawable drawable = new AvatarDrawable();
                    img_avatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                }
            }
            int photoSize2 = item.getSex();
            if (photoSize2 != 0) {
                tv_gender_age.setVisibility(0);
                if (item.getSex() == 1) {
                    tv_gender_age.setSelected(true);
                } else {
                    tv_gender_age.setSelected(false);
                }
                tv_gender_age.setText(TimeUtils.getAgeByBirthday(new Date(((long) item.getBirthday()) * 1000)) + "");
                tv_gender_age.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
            } else {
                tv_gender_age.setVisibility(8);
            }
            if (FcFollowedManageActivity.this.canceledFocusUser.size() > 0 && FcFollowedManageActivity.this.canceledFocusUser.contains(Integer.valueOf(item.getUserId()))) {
                tv_attention.setText(LocaleController.getString("attention", R.string.attention));
                tv_attention.setSelected(true);
            } else {
                tv_attention.setText(LocaleController.getString("attentioned", R.string.attentioned));
                tv_attention.setSelected(false);
            }
            tv_attention.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter, im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageLoadMoreListener
        public void loadData(int page) {
            super.loadData(page);
            FcFollowedManageActivity fcFollowedManageActivity = FcFollowedManageActivity.this;
            fcFollowedManageActivity.getFcPageList(page, fcFollowedManageActivity.searchText);
        }
    }

    private class MyAdapter extends PageSelectionAdapter<FcUserInfoBean, PageHolder> {
        public MyAdapter(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(FcFollowedManageActivity.this.mContext).inflate(R.layout.item_attention_manage, parent, false);
            return new PageHolder(view, 0);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, FcUserInfoBean item) {
            BackupImageView img_avatar = (BackupImageView) holder.itemView.findViewById(R.attr.img_avatar);
            TextView tv_nick_name = (TextView) holder.itemView.findViewById(R.attr.tv_nick_name);
            TextView tv_gender_age = (TextView) holder.itemView.findViewById(R.attr.tv_gender_age);
            TextView tv_attention = (TextView) holder.itemView.findViewById(R.attr.tv_attention);
            if (Theme.getCurrentTheme().isLight()) {
                tv_nick_name.setTextColor(FcFollowedManageActivity.this.mContext.getResources().getColor(R.color.color_111111));
            } else {
                tv_nick_name.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            }
            tv_nick_name.setText(StringUtils.handleTextName(ContactsController.formatName(item.getFirstName(), item.getLastName()), 12));
            img_avatar.setRoundRadius(AndroidUtilities.dp(5.0f));
            AvatarPhotoBean avatarPhotoBean = item.getPhoto();
            if (avatarPhotoBean != null) {
                int photoSize = avatarPhotoBean.getSmallPhotoSize();
                int localId = avatarPhotoBean.getSmallLocalId();
                long volumeId = avatarPhotoBean.getSmallVolumeId();
                if (photoSize != 0 && volumeId != 0 && avatarPhotoBean.getAccess_hash() != 0) {
                    TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                    inputPeer.user_id = item.getUserId();
                    inputPeer.access_hash = item.getAccessHash();
                    ImageLocation imageLocation = new ImageLocation();
                    imageLocation.dc_id = 2;
                    imageLocation.photoPeer = inputPeer;
                    imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                    imageLocation.location.local_id = localId;
                    imageLocation.location.volume_id = volumeId;
                    AvatarDrawable drawable = new AvatarDrawable();
                    img_avatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                }
            }
            int photoSize2 = item.getSex();
            if (photoSize2 != 0) {
                tv_gender_age.setVisibility(0);
                if (item.getSex() == 1) {
                    tv_gender_age.setSelected(true);
                } else {
                    tv_gender_age.setSelected(false);
                }
                tv_gender_age.setText(TimeUtils.getAgeByBirthday(new Date(((long) item.getBirthday()) * 1000)) + "");
                tv_gender_age.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
            } else {
                tv_gender_age.setVisibility(8);
            }
            if (FcFollowedManageActivity.this.canceledFocusUser.size() > 0 && FcFollowedManageActivity.this.canceledFocusUser.contains(Integer.valueOf(item.getUserId()))) {
                tv_attention.setText(LocaleController.getString("attention", R.string.attention));
                tv_attention.setSelected(false);
            } else {
                tv_attention.setText(LocaleController.getString("attentioned", R.string.attentioned));
                tv_attention.setSelected(true);
            }
            tv_attention.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter, im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageLoadMoreListener
        public void loadData(int page) {
            super.loadData(page);
            FcFollowedManageActivity.this.getFcPageList(page, "");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getFcPageList(int pageNo, String UserName) {
        Observable<BResponse<ResponseFcAttentionUsertBeanV1>> observable = ApiFactory.getInstance().getApiMomentForum().getFollowedUserList(pageNo * 20, 20, UserName);
        RxHelper.getInstance().sendRequest(this.TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$IR3stpYdfiDFvsOh7_ou2G81aoQ
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getFcPageList$3$FcFollowedManageActivity((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$qMI6UIj-xPHhmCWQOgCNOUCwD30
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getFcPageList$4$FcFollowedManageActivity((Throwable) obj);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$getFcPageList$3$FcFollowedManageActivity(BResponse response) throws Exception {
        if (response != null && response.isState()) {
            ResponseFcAttentionUsertBeanV1 mFclistBeanList = (ResponseFcAttentionUsertBeanV1) response.Data;
            if (response.Data != 0 && !this.searchWas) {
                this.myAdapter.addData((List) mFclistBeanList.Users);
            } else {
                this.fl_search_cover.setVisibility(8);
                this.mysearchAdapter.addData((List) mFclistBeanList.Users);
            }
        }
    }

    public /* synthetic */ void lambda$getFcPageList$4$FcFollowedManageActivity(Throwable throwable) throws Exception {
        if (!this.searchWas) {
            this.myAdapter.showError(RxHelper.getInstance().getErrorInfo(throwable));
            return;
        }
        if (this.actionBar.getVisibility() == 4) {
            showTitle(this.fragmentView);
            this.searchView.cancelFocus();
            this.fl_search_container.setBackgroundColor(Theme.getColor(Theme.key_list_decorationBackground));
            this.fl_search_cover.setVisibility(8);
        }
        this.myAdapter.showError(LocaleController.getString("request_fialed", R.string.fc_request_fialed));
    }

    protected void doFollow(final int position, final FcUserInfoBean fcUserInfoBean) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("FollowUID", Integer.valueOf(fcUserInfoBean.getUserId())).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doFollow(requestBody);
        RxHelper.getInstance().sendRequestNoData(this.TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$Z1xi0GQ26dutWYspA5YevH2xpH4
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$doFollow$5$FcFollowedManageActivity(position, fcUserInfoBean, (BResponseNoData) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$3yjQsvuEc_kWfawRoB-1Foy5GL0
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                FcToastUtils.show(R.string.friendscircle_attention_user_fail);
            }
        });
    }

    public /* synthetic */ void lambda$doFollow$5$FcFollowedManageActivity(int position, FcUserInfoBean fcUserInfoBean, BResponseNoData responseNoData) throws Exception {
        if (responseNoData != null) {
            if (responseNoData.isState()) {
                FcToastUtils.show((CharSequence) responseNoData.Message);
                this.myAdapter.notifyItemChanged(position);
                if (this.canceledFocusUser.contains(Integer.valueOf(fcUserInfoBean.getUserId()))) {
                    ArrayList<Integer> arrayList = this.canceledFocusUser;
                    arrayList.remove(arrayList.indexOf(Integer.valueOf(fcUserInfoBean.getUserId())));
                }
                if (this.searchWas) {
                    this.mysearchAdapter.notifyDataSetChanged();
                } else {
                    this.myAdapter.notifyDataSetChanged();
                }
                NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcFollowStatusUpdate, this.TAG, Long.valueOf(fcUserInfoBean.getUserId()), true);
                return;
            }
            FcToastUtils.show((CharSequence) responseNoData.Message);
            return;
        }
        FcToastUtils.show(R.string.friendscircle_attention_user_fail);
    }

    protected void doCancelFocusUser(final int position, final FcUserInfoBean fcUserInfoBean) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("FollowUID", Integer.valueOf(fcUserInfoBean.getUserId())).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doCancelFollowed(requestBody);
        RxHelper.getInstance().sendRequestNoData(this.TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$auk6h89viUjEMWyVeUdo7FxNi2g
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$doCancelFocusUser$7$FcFollowedManageActivity(position, fcUserInfoBean, (BResponseNoData) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcFollowedManageActivity$gMuuobrowTceF-M8kv68H-DeLec
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                FcToastUtils.show(R.string.friendscircle_attention_user_cancel_fail);
            }
        });
    }

    public /* synthetic */ void lambda$doCancelFocusUser$7$FcFollowedManageActivity(int position, FcUserInfoBean fcUserInfoBean, BResponseNoData responseNoData) throws Exception {
        if (responseNoData != null) {
            if (responseNoData.isState()) {
                this.myAdapter.notifyItemChanged(position);
                FcToastUtils.show((CharSequence) responseNoData.Message);
                if (!this.canceledFocusUser.contains(Integer.valueOf(fcUserInfoBean.getUserId()))) {
                    this.canceledFocusUser.add(Integer.valueOf(fcUserInfoBean.getUserId()));
                }
                if (this.searchWas) {
                    this.mysearchAdapter.notifyDataSetChanged();
                } else {
                    this.myAdapter.notifyDataSetChanged();
                }
                NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcFollowStatusUpdate, this.TAG, Long.valueOf(fcUserInfoBean.getUserId()), false);
                return;
            }
            FcToastUtils.show((CharSequence) responseNoData.Message);
            return;
        }
        FcToastUtils.show(R.string.friendscircle_attention_user_cancel_fail);
    }
}
