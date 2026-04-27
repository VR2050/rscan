package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.GradientDrawable;
import android.media.ThumbnailUtils;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.Editable;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.TranslateAnimation;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.OnClick;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcEntitysBean;
import com.bjz.comm.net.bean.FcMediaBean;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespTopicBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.premission.PermissionManager;
import com.bjz.comm.net.premission.observer.PermissionObserver;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.bjz.comm.net.utils.RxHelper;
import com.blankj.utilcode.util.SizeUtils;
import com.google.android.exoplayer2.util.Log;
import com.google.gson.Gson;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.socks.library.KLog;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.javaBean.fc.FriendsCirclePublishBean;
import im.uwrkaxlmjj.javaBean.fc.PublishFcBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ImageUtils;
import im.uwrkaxlmjj.messenger.utils.TaskQueue;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.AtUserMethod;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.MethodContext;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.User;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.FlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagFlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureRecyclerView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.BottomDeleteDragListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryRoundButtonDrawable;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.io.FileNotFoundException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class FcPublishActivity extends CommFcActivity implements ChooseAtContactsActivity.ContactsActivityDelegate, PermissionObserver, NotificationCenter.NotificationCenterDelegate {
    private static final int REQUEST_LOCATION_PERMISSIONS = 1;
    private byte ATTACH_TYPE_IMAGE;
    private byte ATTACH_TYPE_NONE;
    private byte ATTACH_TYPE_VIDEO;
    private byte PUBLISH_BUTTON;
    private Adapter adapter;
    private AddPictureRecyclerView addpicturerecycleview_photo;

    @BindView(R.attr.biv_video)
    ImageView bivVideo;

    @BindView(R.attr.biv_video_h)
    ImageView bivVideoH;
    private ConstraintLayout constraintBottomParent;
    private int currentSelectMediaType;
    private int currentUploadIndex;

    @BindView(R.attr.et_content)
    EditText etContent;
    private ImageSelectorActivity imageSelectorAlert;
    private int imgWidth;
    private boolean isPublishing;
    private ImageView ivBottmTrash;
    PublishHandler mHandler;
    private TreeMap<String, String> mMapPhotos;
    private ArrayList<FcMediaBean> mMediasList;
    private String mStrContent;
    private TaskQueue<String[]> mTaskQueue;
    private int maxContentLen;
    private byte mbytAttachType;
    private PublishMenuAdapter menuAdapter;
    private MethodContext methodContext;
    private int miVideoHeight;
    private int miVideoWidth;
    private ArrayList<MediaController.PhotoEntry> photoEntries;
    private MediaController.PhotoEntry photoEntryVideo;
    private ArrayList<Map.Entry<String, String>> photoList;
    private ImagePreSelectorActivity preSelectorActivity;
    private AlertDialog progressDialog;
    private MryTextView publishItemView;

    @BindView(R.attr.rl_container)
    RelativeLayout rlContainer;
    private RelativeLayout rl_multimedia;

    @BindView(R.attr.rvMenu)
    RecyclerListView rvMenu;
    private HashMap<Object, Object> selectedPhotos;
    private ArrayList<Object> selectedPhotosOrder;
    private TagAdapter tagadapter;
    private TagFlowLayout tagflow_topics;
    private TextView tvBottomTrash;
    private PublishFcBean unPublishFcBean;
    private static final String TAG = FcPublishActivity.class.getSimpleName();
    private static final String[] NEEDED_PERMISSIONS = {PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"};

    static /* synthetic */ int access$1308(FcPublishActivity x0) {
        int i = x0.currentUploadIndex;
        x0.currentUploadIndex = i + 1;
        return i;
    }

    public FcPublishActivity() {
        this.PUBLISH_BUTTON = (byte) 1;
        this.ATTACH_TYPE_NONE = (byte) 0;
        this.ATTACH_TYPE_IMAGE = (byte) 1;
        this.ATTACH_TYPE_VIDEO = (byte) 2;
        this.adapter = null;
        this.photoEntries = new ArrayList<>();
        this.photoEntryVideo = null;
        this.progressDialog = null;
        this.mStrContent = null;
        this.mbytAttachType = this.ATTACH_TYPE_NONE;
        this.mMapPhotos = new TreeMap<>();
        this.mTaskQueue = new TaskQueue<>();
        this.isPublishing = false;
        this.mMediasList = new ArrayList<>();
        this.currentSelectMediaType = 0;
        this.maxContentLen = 2000;
        this.currentUploadIndex = 0;
        this.mHandler = new PublishHandler(this);
    }

    public FcPublishActivity(PublishFcBean publishFcBean) {
        this.PUBLISH_BUTTON = (byte) 1;
        this.ATTACH_TYPE_NONE = (byte) 0;
        this.ATTACH_TYPE_IMAGE = (byte) 1;
        this.ATTACH_TYPE_VIDEO = (byte) 2;
        this.adapter = null;
        this.photoEntries = new ArrayList<>();
        this.photoEntryVideo = null;
        this.progressDialog = null;
        this.mStrContent = null;
        this.mbytAttachType = this.ATTACH_TYPE_NONE;
        this.mMapPhotos = new TreeMap<>();
        this.mTaskQueue = new TaskQueue<>();
        this.isPublishing = false;
        this.mMediasList = new ArrayList<>();
        this.currentSelectMediaType = 0;
        this.maxContentLen = 2000;
        this.currentUploadIndex = 0;
        this.mHandler = new PublishHandler(this);
        this.unPublishFcBean = publishFcBean;
    }

    public FcPublishActivity(ImagePreSelectorActivity preSelectorActivity, HashMap<Object, Object> selectedPhotos, ArrayList<Object> selectedPhotosOrder, int currentSelectMediaType) {
        this.PUBLISH_BUTTON = (byte) 1;
        this.ATTACH_TYPE_NONE = (byte) 0;
        this.ATTACH_TYPE_IMAGE = (byte) 1;
        this.ATTACH_TYPE_VIDEO = (byte) 2;
        this.adapter = null;
        this.photoEntries = new ArrayList<>();
        this.photoEntryVideo = null;
        this.progressDialog = null;
        this.mStrContent = null;
        this.mbytAttachType = this.ATTACH_TYPE_NONE;
        this.mMapPhotos = new TreeMap<>();
        this.mTaskQueue = new TaskQueue<>();
        this.isPublishing = false;
        this.mMediasList = new ArrayList<>();
        this.currentSelectMediaType = 0;
        this.maxContentLen = 2000;
        this.currentUploadIndex = 0;
        this.mHandler = new PublishHandler(this);
        this.preSelectorActivity = preSelectorActivity;
        this.selectedPhotos = selectedPhotos;
        this.selectedPhotosOrder = selectedPhotosOrder;
        this.currentSelectMediaType = currentSelectMediaType;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_friendscircle_publishv1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.selectedTopicSuccessToPublish);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.selectedTopicSuccessToPublish);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        initActionBar();
        useButterKnife();
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.addpicturerecycleview_photo = (AddPictureRecyclerView) this.fragmentView.findViewById(R.attr.addpicturerecycleview_photo);
        this.constraintBottomParent = (ConstraintLayout) this.fragmentView.findViewById(R.attr.constraintBottomParent);
        this.ivBottmTrash = (ImageView) this.fragmentView.findViewById(R.attr.ivBottmTrash);
        this.tvBottomTrash = (TextView) this.fragmentView.findViewById(R.attr.tvBottomTrash);
        this.rl_multimedia = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_multimedia);
        this.tvBottomTrash.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        TagFlowLayout tagFlowLayout = (TagFlowLayout) this.fragmentView.findViewById(R.attr.tagflow_topics);
        this.tagflow_topics = tagFlowLayout;
        setTopicsInfo(tagFlowLayout);
        this.rl_multimedia.bringToFront();
        this.addpicturerecycleview_photo.bringToFront();
        Adapter adapter = new Adapter(this.mContext, getParentActivity());
        this.adapter = adapter;
        this.addpicturerecycleview_photo.setAdapter(adapter);
        this.addpicturerecycleview_photo.setLayoutManager(new GridLayoutManager(this.mContext, 3));
        this.adapter.setOnItemClickListener(new AddPictureTouchAdapter.AddPictureOnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$hjL1FLCWGgrvB_QRqoyHc-0rxK4
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter.AddPictureOnItemClickListener
            public final void onItemClick(Object obj, boolean z) {
                this.f$0.lambda$initView$0$FcPublishActivity((SendMessagesHelper.SendingMediaInfo) obj, z);
            }
        });
        this.addpicturerecycleview_photo.setDragListener(new BottomDeleteDragListener<SendMessagesHelper.SendingMediaInfo, Holder>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.BottomDeleteDragListener, im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.DragListener
            public boolean stateIsInSpecialArea(boolean isInArea, boolean isFingerUp, int position) {
                FcPublishActivity.this.ivBottmTrash.setSelected(isInArea);
                FcPublishActivity.this.constraintBottomParent.setSelected(isInArea);
                if (isInArea) {
                    FcPublishActivity.this.tvBottomTrash.setText(LocaleController.getString("griptodelete", R.string.griptodelete));
                    if (isFingerUp && FcPublishActivity.this.adapter != null && FcPublishActivity.this.photoEntries.size() > 0) {
                        FcPublishActivity.this.photoEntries.remove(position);
                        return false;
                    }
                    return false;
                }
                FcPublishActivity.this.tvBottomTrash.setText(LocaleController.getString("dragtheretodelete", R.string.dragtheretodelete));
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.DragListener
            public boolean canDrag(Holder viewHolder, int position, SendMessagesHelper.SendingMediaInfo sendingMediaInfo) {
                return viewHolder.getItemViewType() != 1;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.DragListener
            public void onPreDrag() {
                FcPublishActivity.doTransAniAfterGone(FcPublishActivity.this.constraintBottomParent, true);
                AndroidUtilities.hideKeyboard(FcPublishActivity.this.etContent);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.DragListener
            public void onDraging() {
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.DragListener
            public void onReleasedDrag() {
                FcPublishActivity.doTransAniAfterGone(FcPublishActivity.this.constraintBottomParent, false);
                FcPublishActivity.this.setPublishButtonStatus();
            }
        });
        this.etContent.setHint(LocaleController.getString("friendscircle_publish_content_tip", R.string.friendscircle_publish_content_tip));
        initListenter();
        if (Theme.getCurrentTheme().isDark()) {
            this.etContent.setTextColor(this.mContext.getResources().getColor(R.color.white));
            this.etContent.setHintTextColor(this.mContext.getResources().getColor(R.color.white));
        } else {
            this.etContent.setTextColor(this.mContext.getResources().getColor(R.color.color_333333));
            this.etContent.setHintTextColor(this.mContext.getResources().getColor(R.color.color_D5D5D5));
        }
        MethodContext methodContext = new MethodContext();
        this.methodContext = methodContext;
        methodContext.setMethod(AtUserMethod.INSTANCE);
        this.methodContext.init(this.etContent);
        this.etContent.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.2
            private int beforeCount;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                this.beforeCount = s.toString().length();
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String setMsg = s.toString();
                if (setMsg.length() >= this.beforeCount && FcPublishActivity.this.etContent.getSelectionEnd() > 0 && setMsg.charAt(FcPublishActivity.this.etContent.getSelectionEnd() - 1) == '@') {
                    Bundle args = new Bundle();
                    ChooseAtContactsActivity chooseAtContactsActivity = new ChooseAtContactsActivity(args);
                    chooseAtContactsActivity.setDelegate(FcPublishActivity.this);
                    FcPublishActivity.this.presentFragment(chooseAtContactsActivity, false);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                FcPublishActivity.this.setPublishButtonStatus();
            }
        });
        this.menuAdapter = new PublishMenuAdapter(getParentActivity(), 1).setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$GLmhygw682tG05LIjMb5lvBA0gQ
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initView$1$FcPublishActivity(view, i);
            }
        }).setMenuUserItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$kyUj0PBvggbEzDdI8qiNVjJ3SX8
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                FcPublishActivity.lambda$initView$2(view, i);
            }
        });
        this.rvMenu.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        this.rvMenu.setAdapter(this.menuAdapter);
    }

    public /* synthetic */ void lambda$initView$0$FcPublishActivity(SendMessagesHelper.SendingMediaInfo data, boolean isAddPictureItem) {
        if (isAddPictureItem) {
            openAttachMenu();
        }
    }

    public /* synthetic */ void lambda$initView$1$FcPublishActivity(View view, int type) {
        PublishMenuAdapter.Menu menu;
        if (type == 0) {
            ToastUtils.show((CharSequence) "developing");
            return;
        }
        if (type == 1) {
            checkPermission();
            return;
        }
        if (type != 2) {
            if (type == 3) {
                ToastUtils.show((CharSequence) "developing");
            }
        } else {
            PublishMenuAdapter publishMenuAdapter = this.menuAdapter;
            if (publishMenuAdapter != null && (menu = publishMenuAdapter.getMenu(2)) != null) {
                presentFragment(new AddTopicActivity(((PublishMenuAdapter.MenuTopic) menu).topicMap));
            }
        }
    }

    static /* synthetic */ void lambda$initView$2(View view, int type) {
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackButtonImage(R.drawable.ic_fc_back);
        ((ImageView) this.actionBar.getBackButton()).setColorFilter(Theme.getCurrentTheme().isLight() ? -6710887 : Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.SRC_IN);
        this.actionBar.setTitle(LocaleController.getString("friendscircle_publish_title", R.string.friendscircle_publish_title));
        this.actionBar.setDelegate(new ActionBar.ActionBarDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$QlgXPF9N6CbUblcGIKf15-qboVo
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarDelegate
            public final void onSearchFieldVisibilityChanged(boolean z) {
                this.f$0.lambda$initActionBar$3$FcPublishActivity(z);
            }
        });
        MryTextView btnPublic = new MryTextView(this.mContext);
        GradientDrawable gradientDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, new int[]{this.mContext.getResources().getColor(R.color.color_87DFFA), this.mContext.getResources().getColor(R.color.color_2ECEFD)});
        btnPublic.setText(LocaleController.getString("publish", R.string.publish));
        btnPublic.setTextSize(13.0f);
        btnPublic.setTextColor(this.mContext.getResources().getColor(R.color.color_80FFFFFF));
        btnPublic.setGravity(17);
        gradientDrawable.setCornerRadius(AndroidUtilities.dp(50.0f));
        gradientDrawable.setShape(0);
        btnPublic.setBackground(gradientDrawable);
        FrameLayout.LayoutParams layoutParams = LayoutHelper.createFrame(56, 25.0f);
        layoutParams.rightMargin = AndroidUtilities.dp(15.0f);
        layoutParams.topMargin = AndroidUtilities.dp(6.0f);
        ActionBarMenu menu = this.actionBar.createMenu();
        this.publishItemView = (MryTextView) menu.addItemView(1, btnPublic, layoutParams);
    }

    public /* synthetic */ void lambda$initActionBar$3$FcPublishActivity(boolean visible) {
        this.actionBar.getBackButton().setVisibility(visible ? 0 : 8);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        if (this.unPublishFcBean != null) {
            loadUnPublishData();
            return;
        }
        HashMap<Object, Object> map = this.selectedPhotos;
        if (map != null && map.size() > 0) {
            dealSelectPhotoResult(this.selectedPhotos, this.selectedPhotosOrder);
            setPublishButtonStatus();
        }
    }

    private void loadUnPublishData() {
        String content = this.unPublishFcBean.getContent();
        if (!TextUtils.isEmpty(content)) {
            this.etContent.setText(content);
            ArrayList<FcEntitysBean> entitys = this.unPublishFcBean.getEntitys();
            for (FcEntitysBean fcEntitysBean : entitys) {
                if (fcEntitysBean != null) {
                    Editable text = this.etContent.getText();
                    if (text instanceof SpannableStringBuilder) {
                        User insertAtUserSpan = new User(fcEntitysBean.getUserID(), fcEntitysBean.getNickName(), fcEntitysBean.getUserName(), fcEntitysBean.getShowName(), fcEntitysBean.getAccessHash());
                        Spannable spannable = this.methodContext.newSpannable(insertAtUserSpan);
                        text.replace(fcEntitysBean.getOffsetStart(), fcEntitysBean.getOffsetEnd(), spannable);
                    }
                }
            }
        }
        HashMap<Integer, MediaController.PhotoEntry> selectedPhotos = this.unPublishFcBean.getSelectedPhotos();
        ArrayList<Integer> selectedPhotosOrder = this.unPublishFcBean.getSelectedPhotosOrder();
        if (selectedPhotos != null && !selectedPhotos.isEmpty() && selectedPhotosOrder != null && !selectedPhotosOrder.isEmpty()) {
            HashMap<Object, Object> sMap = new HashMap<>();
            ArrayList<Object> sOrder = new ArrayList<>();
            for (Map.Entry<Integer, MediaController.PhotoEntry> next : selectedPhotos.entrySet()) {
                if (next != null) {
                    sMap.put(next.getKey(), next.getValue());
                    sOrder.add(next.getKey());
                }
            }
            this.selectedPhotos = sMap;
            this.selectedPhotosOrder = sOrder;
            this.currentSelectMediaType = this.unPublishFcBean.getCurrentSelectMediaType();
            dealSelectPhotoResult(this.selectedPhotos, this.selectedPhotosOrder);
        }
        HashMap<String, RespTopicBean.Item> topic = this.unPublishFcBean.getTopic();
        PublishMenuAdapter publishMenuAdapter = this.menuAdapter;
        if (publishMenuAdapter != null) {
            publishMenuAdapter.updateTopicRow(topic);
            this.tagadapter.setData(this.menuAdapter.getTopicRowRespTopicsList());
            this.tagadapter.notifyDataChanged();
        }
        setPublishButtonStatus();
    }

    public static void doTransAniAfterGone(final View view, final boolean show) {
        TranslateAnimation t;
        if (view == null) {
            return;
        }
        if (show) {
            t = new TranslateAnimation(0.0f, 0.0f, 0.0f, SizeUtils.dp2px(-60.0f));
        } else {
            t = new TranslateAnimation(0.0f, 0.0f, SizeUtils.dp2px(-60.0f), 0.0f);
        }
        t.setFillAfter(true);
        t.setDuration(300L);
        t.setRepeatCount(0);
        t.setRepeatMode(2);
        t.setAnimationListener(new Animation.AnimationListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.3
            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationStart(Animation animation) {
                if (show) {
                    view.setVisibility(0);
                }
            }

            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationEnd(Animation animation) {
                if (!show) {
                    view.setVisibility(8);
                    view.clearAnimation();
                }
            }

            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationRepeat(Animation animation) {
            }
        });
        view.startAnimation(t);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity$4, reason: invalid class name */
    class AnonymousClass4 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass4() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) throws JSONException {
            if (id == -1) {
                if (FcPublishActivity.this.publishItemView.isSelected()) {
                    FcPublishActivity.this.exitProcess();
                    return;
                } else {
                    FcPublishActivity.this.finishFragment();
                    return;
                }
            }
            if (id == FcPublishActivity.this.PUBLISH_BUTTON && !FcPublishActivity.this.isPublishing) {
                if ((FcPublishActivity.this.photoEntryVideo != null && !FcPublishActivity.this.photoEntryVideo.path.equals("")) || FcPublishActivity.this.photoEntries.size() != 0 || !TextUtils.isEmpty(FcPublishActivity.this.etContent.getText().toString().trim())) {
                    FcPublishActivity.this.mMapPhotos.clear();
                    FcPublishActivity.this.mMediasList.clear();
                    OkHttpUtils.getInstance().cancelTag("upload");
                    FcPublishActivity.this.currentUploadIndex = 0;
                    FcPublishActivity fcPublishActivity = FcPublishActivity.this;
                    if (!fcPublishActivity.isNetworkConnected(fcPublishActivity.mContext)) {
                        FcToastUtils.show((CharSequence) LocaleController.getString("error_net", R.string.error_net));
                        return;
                    }
                    if (TextUtils.isEmpty(FcPublishActivity.this.etContent.getText().toString().trim()) && ((FcPublishActivity.this.photoEntryVideo == null || FcPublishActivity.this.photoEntryVideo.path.equals("")) && FcPublishActivity.this.photoEntries.size() <= 0)) {
                        return;
                    }
                    Editable text = FcPublishActivity.this.etContent.getText();
                    if (!TextUtils.isEmpty(text.toString().trim())) {
                        FcPublishActivity.this.mStrContent = text.toString().trim();
                    }
                    if (FcPublishActivity.this.mStrContent == null || FcPublishActivity.this.mStrContent.length() <= FcPublishActivity.this.maxContentLen) {
                        if (FcPublishActivity.this.photoEntryVideo == null || FcPublishActivity.this.photoEntryVideo.path.equals("")) {
                            if (FcPublishActivity.this.photoEntries.size() > 0) {
                                try {
                                    if (FcPublishActivity.this.progressDialog == null) {
                                        FcPublishActivity.this.progressDialog = new AlertDialog(FcPublishActivity.this.getParentActivity(), 3);
                                    }
                                    FcPublishActivity.this.progressDialog.show();
                                    FcPublishActivity.this.progressDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$4$2YtcdK4STwqaS3CyUmjxKSTjatI
                                        @Override // android.content.DialogInterface.OnDismissListener
                                        public final void onDismiss(DialogInterface dialogInterface) {
                                            OkHttpUtils.getInstance().getOkHttpClient().dispatcher().cancelAll();
                                        }
                                    });
                                } catch (Exception e) {
                                }
                                FcPublishActivity fcPublishActivity2 = FcPublishActivity.this;
                                fcPublishActivity2.mbytAttachType = fcPublishActivity2.ATTACH_TYPE_IMAGE;
                                FcPublishActivity fcPublishActivity3 = FcPublishActivity.this;
                                fcPublishActivity3.processPhotos(fcPublishActivity3.mMapPhotos);
                                return;
                            }
                            if (!TextUtils.isEmpty(FcPublishActivity.this.etContent.getText().toString().trim())) {
                                try {
                                    if (FcPublishActivity.this.progressDialog == null) {
                                        FcPublishActivity.this.progressDialog = new AlertDialog(FcPublishActivity.this.getParentActivity(), 3);
                                    }
                                    FcPublishActivity.this.progressDialog.show();
                                    FcPublishActivity.this.progressDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$4$i8AnOKyECfSvPbA46nmKB6fDNfw
                                        @Override // android.content.DialogInterface.OnDismissListener
                                        public final void onDismiss(DialogInterface dialogInterface) {
                                            RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(FcPublishActivity.TAG);
                                        }
                                    });
                                } catch (Exception e2) {
                                }
                                FcPublishActivity fcPublishActivity4 = FcPublishActivity.this;
                                fcPublishActivity4.mbytAttachType = fcPublishActivity4.ATTACH_TYPE_NONE;
                                FcPublishActivity.this.sendDataToServer();
                                return;
                            }
                            FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_publish_tips_empty_content", R.string.friendscircle_publish_tips_empty_content));
                            return;
                        }
                        try {
                            if (FcPublishActivity.this.progressDialog == null) {
                                FcPublishActivity.this.progressDialog = new AlertDialog(FcPublishActivity.this.getParentActivity(), 3);
                            }
                            FcPublishActivity.this.progressDialog.show();
                            FcPublishActivity.this.progressDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$4$QZSJQQHqCUgKswXo_z1b2KM0W8Y
                                @Override // android.content.DialogInterface.OnDismissListener
                                public final void onDismiss(DialogInterface dialogInterface) {
                                    OkHttpUtils.getInstance().getOkHttpClient().dispatcher().cancelAll();
                                }
                            });
                        } catch (Exception e3) {
                        }
                        FcPublishActivity fcPublishActivity5 = FcPublishActivity.this;
                        fcPublishActivity5.mbytAttachType = fcPublishActivity5.ATTACH_TYPE_VIDEO;
                        FcPublishActivity.this.processVideo();
                        if (FcPublishActivity.this.mMapPhotos.size() > 0) {
                            String[] arr = {FcPublishActivity.this.photoEntryVideo.path, (String) FcPublishActivity.this.mMapPhotos.get(FcPublishActivity.this.photoEntryVideo.path)};
                            FcPublishActivity.this.mTaskQueue.inputQueue(arr);
                            FcPublishActivity.this.readyUpload();
                            return;
                        }
                        return;
                    }
                    WalletDialog walletDialog = WalletDialogUtil.showWalletDialog((Object) FcPublishActivity.this, "提示", (CharSequence) "你输入的内容不能超过2000个字符", "我知道了", false, (DialogInterface.OnClickListener) null);
                    walletDialog.getPositiveButton().setTextColor(Color.parseColor("#FF2ECEFD"));
                    return;
                }
                FcToastUtils.show((CharSequence) LocaleController.getString("friendscircle_publish_tips_empty_content", R.string.friendscircle_publish_tips_empty_content));
            }
        }
    }

    public void initListenter() {
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass4());
        this.etContent.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.5
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendDataToServer() {
        FriendsCirclePublishBean publishBean;
        this.isPublishing = true;
        FriendsCirclePublishBean publishBean2 = new FriendsCirclePublishBean();
        publishBean2.setUserID(getUserConfig().getCurrentUser().id);
        publishBean2.setPermission(1);
        String replaceStr = this.mStrContent;
        ArrayList<FCEntitysRequest> atUserBeanList = new ArrayList<>();
        final Editable text = this.etContent.getText();
        User[] spans = (User[]) text.getSpans(0, text.length(), User.class);
        if (spans.length > 1) {
            Arrays.sort(spans, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$GdLPYg2yO2PrIa-jWTFHtTdRLmc
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return FcPublishActivity.lambda$sendDataToServer$4(text, (User) obj, (User) obj2);
                }
            });
        }
        int length = spans.length;
        int i = 0;
        while (i < length) {
            User atUserSpan = spans[i];
            FriendsCirclePublishBean publishBean3 = publishBean2;
            FCEntitysRequest fcEntitysRequest = new FCEntitysRequest("@" + atUserSpan.getNickName(), atUserSpan.getUserID(), atUserSpan.getAccessHash());
            atUserBeanList.add(fcEntitysRequest);
            if (!TextUtils.isEmpty(atUserSpan.getUserName())) {
                String s = "@" + atUserSpan.getNickName() + SQLBuilder.PARENTHESES_LEFT + atUserSpan.getUserName() + SQLBuilder.PARENTHESES_RIGHT;
                if (replaceStr.contains(s)) {
                    replaceStr = replaceStr.replace(s, "@" + atUserSpan.getNickName());
                }
            }
            i++;
            publishBean2 = publishBean3;
        }
        FriendsCirclePublishBean publishBean4 = publishBean2;
        if (atUserBeanList.size() <= 0) {
            publishBean = publishBean4;
        } else {
            publishBean = publishBean4;
            publishBean.setEntitys(atUserBeanList);
        }
        publishBean.setContent(replaceStr);
        ArrayList<FcMediaBean> arrayList = this.mMediasList;
        if (arrayList != null && arrayList.size() > 0) {
            if (this.mMediasList.size() > 1) {
                for (int i2 = 0; i2 < this.mMediasList.size(); i2++) {
                    this.mMediasList.get(i2).setSeq(i2);
                }
            }
            publishBean.setMedias(this.mMediasList);
            publishBean.setContentType(this.mMediasList.get(0).getExt());
        }
        Gson gson = new Gson();
        String json = gson.toJson(publishBean);
        Log.d("publish", "json ：" + json);
        RequestBody requestBody = RequestBody.create(MediaType.parse("application/json;charset=utf-8"), json);
        Observable<BResponse<RespFcListBean>> observable = ApiFactory.getInstance().getApiMomentForum().publish(requestBody);
        RxHelper.getInstance().sendRequest(TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$ySrPJvW0iI7iNtdvBbRKM5M2jaA
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$sendDataToServer$8$FcPublishActivity((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$qPjAsWcLTyE2leTJm75QmHk2DPI
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$sendDataToServer$10$FcPublishActivity((Throwable) obj);
            }
        });
    }

    static /* synthetic */ int lambda$sendDataToServer$4(Editable text, User o1, User o2) {
        return text.getSpanStart(o1) - text.getSpanStart(o2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$sendDataToServer$8$FcPublishActivity(BResponse response) throws Exception {
        try {
            if (this.progressDialog != null && this.progressDialog.isShowing()) {
                this.progressDialog.dismiss();
            }
            XDialog.Builder builder = new XDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("image_select_tip", R.string.image_select_tip));
            builder.setOutSideCancel(false);
            if (response.isState()) {
                RespFcListBean data = (RespFcListBean) response.Data;
                if (data != null && data.getForumID() > 0) {
                    if (data.getMedias() != null && data.getMedias().size() != 0) {
                        data.getMedias().get(0).setHeight(this.miVideoHeight);
                        data.getMedias().get(0).setWidth(this.miVideoWidth);
                        data.setComments(new ArrayList<>());
                    }
                    setPublishBack(data);
                    FcToastUtils.show(R.string.friendscircle_publish_success);
                    finishFragment();
                } else {
                    this.isPublishing = false;
                    FcDialogUtil.publishError(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$Xoto3kbJq4ilNrUpvpvnLSrab4c
                        @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                        public final void onClick(View view) {
                            FcPublishActivity.lambda$null$5(view);
                        }
                    }, null);
                }
                return;
            }
            builder.setMessage(response.Message);
            builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$uCmQJToZqZl8lHee_dTjRgEh9Eo
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    FcPublishActivity.lambda$null$6(dialogInterface, i);
                }
            });
            showDialog(builder.create());
            this.isPublishing = false;
        } catch (Exception e) {
            e.printStackTrace();
            resetData();
            FcDialogUtil.publishError(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$4hl2orovjtc-ZDmRVEv9YrAQX-E
                @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                public final void onClick(View view) {
                    FcPublishActivity.lambda$null$7(view);
                }
            }, null);
        }
    }

    static /* synthetic */ void lambda$null$5(View dialog) {
    }

    static /* synthetic */ void lambda$null$6(DialogInterface dialogInterface, int i) {
    }

    static /* synthetic */ void lambda$null$7(View dialog) {
    }

    public /* synthetic */ void lambda$sendDataToServer$10$FcPublishActivity(Throwable throwable) throws Exception {
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null && alertDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
        resetData();
        FcDialogUtil.publishError(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$hRqQDxOJn8J59gDpIvQ-iq1gNJo
            @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
            public final void onClick(View view) {
                FcPublishActivity.lambda$null$9(view);
            }
        }, null);
    }

    static /* synthetic */ void lambda$null$9(View dialog) {
    }

    private void setPublishBack(RespFcListBean data) {
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcPublishSuccess, TAG, data);
    }

    private void resetData() {
        this.isPublishing = false;
        this.mbytAttachType = this.ATTACH_TYPE_NONE;
        this.mTaskQueue.cleanQueue();
        this.mMapPhotos.clear();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getLocationController().startLocationLookupForPeopleNearby(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        getLocationController().startLocationLookupForPeopleNearby(true);
    }

    protected void processPhotos(final Map<String, String> map) {
        Thread a = new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.6
            @Override // java.lang.Runnable
            public void run() throws JSONException, FileNotFoundException {
                boolean z = true;
                if (FcPublishActivity.this.photoEntries != null) {
                    if (FcPublishActivity.this.photoEntries.size() == 1 && ((MediaController.PhotoEntry) FcPublishActivity.this.photoEntries.get(0)).path.toLowerCase().endsWith(".gif")) {
                        String strPath = ((MediaController.PhotoEntry) FcPublishActivity.this.photoEntries.get(0)).path;
                        if (!TextUtils.isEmpty(strPath)) {
                            map.put(strPath, strPath);
                        }
                    } else {
                        int i = 0;
                        while (i < FcPublishActivity.this.photoEntries.size()) {
                            String strThumb = "";
                            String strPhoto = "";
                            String strPath2 = ((MediaController.PhotoEntry) FcPublishActivity.this.photoEntries.get(i)).path;
                            Bitmap bitmap = ImageLoader.loadBitmap(strPath2, null, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), z);
                            if (bitmap == null) {
                                bitmap = ImageLoader.loadBitmap(strPath2, null, 800.0f, 800.0f, z);
                            }
                            TLRPC.PhotoSize size = ImageLoader.scaleAndSaveImage(bitmap, 500.0f, 500.0f, 80, z);
                            if (size != null) {
                                String strCache = (size.location.volume_id != -2147483648L ? FileLoader.getDirectory(0) : FileLoader.getDirectory(4)).getPath();
                                strThumb = strCache + "/" + size.location.volume_id + "_" + size.location.local_id + ".jpg";
                            }
                            TLRPC.PhotoSize size2 = ImageLoader.scaleAndSaveImage(bitmap, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), 80, false, 101, 101);
                            if (size2 != null) {
                                String strCache2 = (size2.location.volume_id != -2147483648L ? FileLoader.getDirectory(0) : FileLoader.getDirectory(4)).getPath();
                                strPhoto = strCache2 + "/" + size2.location.volume_id + "_" + size2.location.local_id + ".jpg";
                            }
                            if (!strPhoto.equals("")) {
                                KLog.e(FcPublishActivity.TAG, "添加map == " + strPhoto);
                                map.put(strPhoto, strThumb);
                            }
                            if (bitmap != null) {
                                bitmap.recycle();
                            }
                            i++;
                            z = true;
                        }
                    }
                }
                Message msg = Message.obtain();
                msg.what = 1;
                FcPublishActivity.this.mHandler.sendMessage(msg);
            }
        });
        a.start();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.ContactsActivityDelegate
    public void didSelectContact(TLRPC.User user) {
        if (user != null && !TextUtils.isEmpty(user.first_name)) {
            String nickName = user.first_name.trim();
            final Editable text = this.etContent.getText();
            if (text instanceof SpannableStringBuilder) {
                int index = text.toString().indexOf("@", this.etContent.getSelectionEnd() - 1);
                if (index != -1) {
                    text.delete(index, index + 1);
                }
                User insertAtUserSpan = new User(user.id, nickName, user.username, "@" + nickName, user.access_hash);
                User[] spans = (User[]) text.getSpans(0, text.length(), User.class);
                Arrays.sort(spans, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$F87CVeGsxLvR1m7GRfDRXNcGOH8
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return FcPublishActivity.lambda$didSelectContact$11(text, (User) obj, (User) obj2);
                    }
                });
                for (User result : spans) {
                    if (TextUtils.equals(result.getShowName(), insertAtUserSpan.getShowName())) {
                        if (result.getUserID() == insertAtUserSpan.getUserID()) {
                            insertAtUserSpan.setShowName(result.getShowName());
                        } else {
                            StringBuilder sb = new StringBuilder();
                            sb.append(insertAtUserSpan.getShowName());
                            sb.append(TextUtils.isEmpty(insertAtUserSpan.getUserName()) ? "" : SQLBuilder.PARENTHESES_LEFT + insertAtUserSpan.getUserName() + SQLBuilder.PARENTHESES_RIGHT);
                            insertAtUserSpan.setShowName(sb.toString());
                        }
                    } else if (result.getUserID() == insertAtUserSpan.getUserID()) {
                        insertAtUserSpan.setShowName(result.getShowName());
                    }
                }
                this.etContent.getText().insert(this.etContent.getSelectionStart(), this.methodContext.newSpannable(insertAtUserSpan)).insert(this.etContent.getSelectionStart(), " ");
            }
        }
    }

    static /* synthetic */ int lambda$didSelectContact$11(Editable text, User o1, User o2) {
        return text.getSpanStart(o1) - text.getSpanStart(o2);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.selectedTopicSuccessToPublish) {
            PublishMenuAdapter publishMenuAdapter = this.menuAdapter;
            if (publishMenuAdapter != null) {
                publishMenuAdapter.updateTopicRow((HashMap) args[0]);
                this.tagadapter.setData(this.menuAdapter.getTopicRowRespTopicsList());
                this.tagadapter.notifyDataChanged();
            }
            setPublishButtonStatus();
        }
    }

    static class PublishHandler extends Handler {
        private final WeakReference<FcPublishActivity> mActivity;

        public PublishHandler(FcPublishActivity activity) {
            this.mActivity = new WeakReference<>(activity);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) throws JSONException {
            super.handleMessage(msg);
            if (msg.what == 1 && this.mActivity.get().mMapPhotos.size() > 0) {
                this.mActivity.get().readyUpload();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processVideo() {
        Bitmap thumb = ThumbnailUtils.createVideoThumbnail(this.photoEntryVideo.path, 1);
        if (thumb != null) {
            TLRPC.PhotoSize size = ImageLoader.scaleAndSaveImage(thumb, 500.0f, 500.0f, 90, true);
            if (size != null) {
                String strCache = FileLoader.getDirectory(size.location.volume_id != -2147483648L ? 0 : 4).getPath();
                this.mMapPhotos.put(this.photoEntryVideo.path, strCache + "/" + size.location.volume_id + "_" + size.location.local_id + ".jpg");
                KLog.d(this.photoEntryVideo.path + "----缩略图----" + strCache + "/" + size.location.volume_id + "_" + size.location.local_id + ".jpg");
            }
            thumb.recycle();
        }
    }

    private void openAttachMenu() {
        if (getParentActivity() == null) {
            return;
        }
        createChatAttachView();
        if (this.adapter.getData().size() == 0) {
            this.imageSelectorAlert.setCurrentSelectMediaType(0);
        } else {
            int i = this.currentSelectMediaType;
            if (i == 1) {
                this.imageSelectorAlert.setCurrentSelectMediaType(i);
            }
        }
        this.imageSelectorAlert.loadGalleryPhotos();
        this.imageSelectorAlert.setMaxSelectedPhotos(9 - this.adapter.getData().size(), true);
        this.imageSelectorAlert.init();
        this.imageSelectorAlert.setCancelable(false);
        showDialog(this.imageSelectorAlert);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setPublishButtonStatus() {
        MediaController.PhotoEntry photoEntry;
        PublishMenuAdapter publishMenuAdapter;
        PublishMenuAdapter publishMenuAdapter2;
        if (TextUtils.isEmpty(this.etContent.getText().toString()) && (((photoEntry = this.photoEntryVideo) == null || photoEntry.path.equals("")) && this.photoEntries.size() <= 0 && (((publishMenuAdapter = this.menuAdapter) == null || publishMenuAdapter.getMenuLocation() == null || !this.menuAdapter.getMenuLocation().hasAddress()) && ((publishMenuAdapter2 = this.menuAdapter) == null || publishMenuAdapter2.getTopicRowTopicsBeanList().isEmpty())))) {
            this.publishItemView.setSelected(false);
            this.publishItemView.setTextColor(this.mContext.getResources().getColor(R.color.color_80FFFFFF));
        } else {
            this.publishItemView.setSelected(true);
            this.publishItemView.setTextColor(this.mContext.getResources().getColor(R.color.white));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createChatAttachView() {
        if (getParentActivity() != null && this.imageSelectorAlert == null) {
            ImageSelectorActivity imageSelectorActivity = new ImageSelectorActivity(getParentActivity(), this, false) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.7
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity, im.uwrkaxlmjj.ui.actionbar.BottomSheet
                public void dismissInternal() {
                    if (FcPublishActivity.this.imageSelectorAlert.isShowing()) {
                        AndroidUtilities.requestAdjustResize(FcPublishActivity.this.getParentActivity(), FcPublishActivity.this.classGuid);
                        for (int i = 0; i < FcPublishActivity.this.photoEntries.size(); i++) {
                            if (((MediaController.PhotoEntry) FcPublishActivity.this.photoEntries.get(i)).isVideo) {
                                super.dismissInternal();
                                return;
                            }
                        }
                        if (FcPublishActivity.this.adapter.getData().size() > 0) {
                            FcPublishActivity.this.setPublishButtonStatus();
                            FcPublishActivity.this.adapter.notifyDataSetChanged();
                        }
                    }
                    FcPublishActivity.this.addpicturerecycleview_photo.setVisibility(0);
                    FcPublishActivity.this.rlContainer.setVisibility(8);
                    super.dismissInternal();
                }
            };
            this.imageSelectorAlert = imageSelectorActivity;
            ImagePreSelectorActivity imagePreSelectorActivity = this.preSelectorActivity;
            if (imagePreSelectorActivity != null) {
                imageSelectorActivity.setImagePreSelectorActivity(imagePreSelectorActivity);
            }
            this.imageSelectorAlert.setDelegate(new ImageSelectorActivity.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.8
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (FcPublishActivity.this.getParentActivity() == null || FcPublishActivity.this.imageSelectorAlert == null) {
                        return;
                    }
                    if (button != 8 && button != 7 && (button != 4 || FcPublishActivity.this.imageSelectorAlert.getSelectedPhotos().isEmpty())) {
                        if (FcPublishActivity.this.imageSelectorAlert != null) {
                            FcPublishActivity.this.imageSelectorAlert.dismissWithButtonClick(button);
                            return;
                        }
                        return;
                    }
                    if (button != 8) {
                        FcPublishActivity.this.imageSelectorAlert.dismiss();
                    }
                    HashMap<Object, Object> selectedPhotos = FcPublishActivity.this.imageSelectorAlert.getSelectedPhotos();
                    ArrayList<Object> selectedPhotosOrder = FcPublishActivity.this.imageSelectorAlert.getSelectedPhotosOrder();
                    if (!selectedPhotos.isEmpty() && !selectedPhotosOrder.isEmpty()) {
                        FcPublishActivity.this.dealSelectPhotoResult(selectedPhotos, selectedPhotosOrder);
                    }
                    if (FcPublishActivity.this.imageSelectorAlert != null) {
                        FcPublishActivity fcPublishActivity = FcPublishActivity.this;
                        fcPublishActivity.currentSelectMediaType = fcPublishActivity.imageSelectorAlert.getCurrentSelectMediaType();
                    }
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity.ChatAttachViewDelegate
                public void didSelectBot(TLRPC.User user) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity.ChatAttachViewDelegate
                public void onCameraOpened() {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity.ChatAttachViewDelegate
                public View getRevealView() {
                    return null;
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImageSelectorActivity.ChatAttachViewDelegate
                public void needEnterComment() {
                    AndroidUtilities.setAdjustResizeToNothing(FcPublishActivity.this.getParentActivity(), FcPublishActivity.this.classGuid);
                    FcPublishActivity.this.fragmentView.requestLayout();
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dealSelectPhotoResult(HashMap<Object, Object> selectedPhotos, ArrayList<Object> selectedPhotosOrder) {
        if (!selectedPhotos.isEmpty() && !selectedPhotosOrder.isEmpty()) {
            for (int a = 0; a < selectedPhotosOrder.size(); a++) {
                Object o = selectedPhotosOrder.get(a);
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) selectedPhotos.get(o);
                if (photoEntry != null) {
                    SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                    MediaController.PhotoEntry photoEntry1 = new MediaController.PhotoEntry(photoEntry.bucketId, photoEntry.imageId, photoEntry.dateTaken, photoEntry.path, photoEntry.orientation, photoEntry.isVideo);
                    if (photoEntry.imagePath != null) {
                        photoEntry1.orientation = 0;
                        info.path = photoEntry.imagePath;
                    } else if (photoEntry.path != null) {
                        info.path = photoEntry.path;
                    }
                    photoEntry1.path = info.path;
                    info.isVideo = photoEntry.isVideo;
                    info.caption = photoEntry.caption != null ? photoEntry.caption.toString() : null;
                    info.entities = photoEntry.entities;
                    info.masks = photoEntry.stickers.isEmpty() ? null : new ArrayList<>(photoEntry.stickers);
                    info.ttl = photoEntry.ttl;
                    info.videoEditedInfo = photoEntry.editedInfo;
                    info.canDeleteAfter = photoEntry.canDeleteAfter;
                    this.photoEntries.add(photoEntry1);
                    if (photoEntry.isVideo) {
                        showVideo(photoEntry);
                    } else {
                        if (info.path.toLowerCase().endsWith("gif")) {
                            this.adapter.setMaxCount(1);
                        } else {
                            this.adapter.setMaxCount(9);
                        }
                        this.adapter.addItem(info);
                    }
                    photoEntry.reset();
                }
            }
        }
    }

    private void showVideo(MediaController.PhotoEntry photoEntry) {
        this.addpicturerecycleview_photo.setVisibility(4);
        this.rlContainer.setVisibility(0);
        if (this.photoEntryVideo == null) {
            MediaController.PhotoEntry photoEntry2 = new MediaController.PhotoEntry(photoEntry.bucketId, photoEntry.imageId, photoEntry.dateTaken, photoEntry.path, photoEntry.orientation, photoEntry.isVideo);
            this.photoEntryVideo = photoEntry2;
            photoEntry2.editedInfo = photoEntry.editedInfo;
        }
        if (photoEntry.editedInfo != null) {
            this.photoEntryVideo.path = photoEntry.editedInfo.originalPath;
            if (photoEntry.editedInfo.rotationValue == 90 || photoEntry.editedInfo.rotationValue == 270) {
                this.miVideoWidth = photoEntry.editedInfo.resultHeight;
                this.miVideoHeight = photoEntry.editedInfo.resultWidth;
            } else {
                this.miVideoWidth = photoEntry.editedInfo.resultWidth;
                this.miVideoHeight = photoEntry.editedInfo.resultHeight;
            }
        } else {
            this.photoEntryVideo.path = photoEntry.path;
            this.miVideoWidth = 0;
            this.miVideoHeight = 0;
        }
        int i = this.miVideoWidth;
        if (i != 0) {
            float aspectRatio = (i * 1.0f) / this.miVideoHeight;
            if (aspectRatio > 1.0f) {
                RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) this.rlContainer.getLayoutParams();
                layoutParams.width = AndroidUtilities.dp(239.0f);
                layoutParams.height = AndroidUtilities.dp(180.0f);
                this.bivVideo.setVisibility(8);
                this.bivVideoH.setVisibility(0);
                ImageUtils.LoadRoundedCornerImg(getParentActivity(), this.bivVideoH, this.photoEntryVideo.path, AndroidUtilities.dp(10.0f));
            } else {
                RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) this.rlContainer.getLayoutParams();
                layoutParams2.width = AndroidUtilities.dp(213.0f);
                layoutParams2.height = AndroidUtilities.dp(300.0f);
                this.bivVideo.setVisibility(0);
                this.bivVideoH.setVisibility(8);
                ImageUtils.LoadRoundedCornerImg(getParentActivity(), this.bivVideo, this.photoEntryVideo.path, AndroidUtilities.dp(10.0f));
            }
        }
        setPublishButtonStatus();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void exitProcess() {
        FcDialogUtil.exitPublish(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$KyResUf_sTEeYsOGCXAv75hOiHY
            @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
            public final void onClick(View view) {
                this.f$0.lambda$exitProcess$12$FcPublishActivity(view);
            }
        }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$M4JnIbMB3FQHRBnwcIsRB1vlnyA
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$exitProcess$13$FcPublishActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$exitProcess$12$FcPublishActivity(View dialog) {
        saveUnPublishData();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.9
            @Override // java.lang.Runnable
            public void run() {
                FcPublishActivity.this.finishFragment();
            }
        }, 1200L);
    }

    public /* synthetic */ void lambda$exitProcess$13$FcPublishActivity(DialogInterface dialog) {
        finishFragment();
    }

    private void saveUnPublishData() {
        PublishMenuAdapter.Menu menu;
        PublishFcBean publishBean = new PublishFcBean();
        publishBean.setPermission(1);
        ArrayList<FcEntitysBean> atUserBeanList = new ArrayList<>();
        final Editable text = this.etContent.getText();
        User[] spans = (User[]) text.getSpans(0, text.length(), User.class);
        if (spans.length > 1) {
            Arrays.sort(spans, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$YTyrXoWaSDDT5hG3FpYdrPTd_dY
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return FcPublishActivity.lambda$saveUnPublishData$14(text, (User) obj, (User) obj2);
                }
            });
        }
        for (User atUserSpan : spans) {
            FcEntitysBean fcEntitysBean = new FcEntitysBean(atUserSpan.getUserID(), atUserSpan.getNickName(), atUserSpan.getUserName(), atUserSpan.getShowName(), atUserSpan.getAccessHash(), text.getSpanStart(atUserSpan), text.getSpanEnd(atUserSpan));
            atUserBeanList.add(fcEntitysBean);
        }
        if (atUserBeanList.size() > 0) {
            publishBean.setEntitys(atUserBeanList);
        }
        if (!TextUtils.isEmpty(text.toString().trim())) {
            publishBean.setContent(text.toString().trim());
        }
        HashMap<Integer, MediaController.PhotoEntry> selectedPhotos = new HashMap<>();
        ArrayList<Integer> selectedPhotosOrder = new ArrayList<>();
        MediaController.PhotoEntry photoEntry = this.photoEntryVideo;
        if (photoEntry != null && !TextUtils.isEmpty(photoEntry.path)) {
            selectedPhotos.put(Integer.valueOf(this.photoEntryVideo.imageId), this.photoEntryVideo);
            selectedPhotosOrder.add(Integer.valueOf(this.photoEntryVideo.imageId));
        } else {
            ArrayList<MediaController.PhotoEntry> arrayList = this.photoEntries;
            if (arrayList != null && arrayList.size() > 0) {
                for (MediaController.PhotoEntry photoEntry2 : this.photoEntries) {
                    selectedPhotos.put(Integer.valueOf(photoEntry2.imageId), photoEntry2);
                    selectedPhotosOrder.add(Integer.valueOf(photoEntry2.imageId));
                }
            }
        }
        if (selectedPhotos.size() > 0) {
            publishBean.setSelectedPhotos(selectedPhotos);
            publishBean.setSelectedPhotosOrder(selectedPhotosOrder);
            publishBean.setCurrentSelectMediaType(this.currentSelectMediaType);
        }
        PublishMenuAdapter publishMenuAdapter = this.menuAdapter;
        if (publishMenuAdapter != null && (menu = publishMenuAdapter.getMenu(2)) != null) {
            publishBean.setTopic(((PublishMenuAdapter.MenuTopic) menu).topicMap);
        }
        String s = new Gson().toJson(publishBean);
        AppPreferenceUtil.putString("PublishFcBean", s);
    }

    static /* synthetic */ int lambda$saveUnPublishData$14(Editable text, User o1, User o2) {
        return text.getSpanStart(o1) - text.getSpanStart(o2);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (this.publishItemView.isSelected()) {
            exitProcess();
            return false;
        }
        return super.onBackPressed();
    }

    @OnClick({R.attr.biv_video, R.attr.biv_video_h, R.attr.iv_close})
    public void onViewClicked(View view) {
        switch (view.getId()) {
            case R.attr.biv_video /* 2131296395 */:
            case R.attr.biv_video_h /* 2131296396 */:
                if (this.photoEntries != null) {
                    if (this.imageSelectorAlert == null) {
                        createChatAttachView();
                    }
                    this.photoEntries.clear();
                    this.photoEntries.add(this.photoEntryVideo);
                    this.imageSelectorAlert.previewSelectedPhotos(0, this.photoEntries);
                }
                break;
            case R.attr.iv_close /* 2131296792 */:
                FcDialogUtil.isDeleteThisVideo(this, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$S2bqAmObO-d1Bsb_lCQdXa0LO-0
                    @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onViewClicked$15$FcPublishActivity(view2);
                    }
                }, null);
                break;
        }
    }

    public /* synthetic */ void lambda$onViewClicked$15$FcPublishActivity(View dialog) {
        this.photoEntries.clear();
        this.adapter.notifyDataSetChanged();
        this.rlContainer.setVisibility(8);
        this.addpicturerecycleview_photo.setVisibility(0);
        this.photoEntryVideo.path = "";
        setPublishButtonStatus();
    }

    private void checkPermission() {
        PermissionManager.getInstance(this.mContext).requestPermission(this, 1, NEEDED_PERMISSIONS);
    }

    @Override // com.bjz.comm.net.premission.observer.PermissionObserver
    public void onRequestPermissionSuccess(int flag) {
    }

    @Override // com.bjz.comm.net.premission.observer.PermissionObserver
    public void onRequestPermissionFail(int flag) {
    }

    public class Adapter extends AddPictureTouchAdapter<SendMessagesHelper.SendingMediaInfo, Holder> {
        int screenWidth;

        public Adapter(Context context, Activity mActivity) {
            super(context);
            this.screenWidth = Util.getScreenWidth(mActivity);
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (checkIsFull()) {
                return 0;
            }
            return ((getData() == null || getDataCount() < 1 || position != 0 || !getData().get(0).path.toLowerCase().endsWith("gif")) && getItemCount() != 0 && position == getItemCount() - 1) ? 1 : 0;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (getDataCount() < 9) {
                if (getData() != null && getDataCount() == 1 && getData().get(0).path.toLowerCase().endsWith("gif")) {
                    return getDataCount();
                }
                return getDataCount() + 1;
            }
            return getDataCount();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public Holder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(FcPublishActivity.this.mContext).inflate(R.layout.item_friendscircle_publishv1, parent, false);
            RecyclerView.LayoutParams lp = new RecyclerView.LayoutParams(-1, -2);
            lp.leftMargin = AndroidUtilities.dp(5.0f);
            lp.topMargin = AndroidUtilities.dp(5.0f);
            lp.rightMargin = AndroidUtilities.dp(5.0f);
            lp.bottomMargin = AndroidUtilities.dp(5.0f);
            view.setMinimumHeight(AndroidUtilities.dp(115.0f));
            view.setLayoutParams(lp);
            return new Holder(view);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter
        public void onBindViewHolder(Holder holder, final int position, SendMessagesHelper.SendingMediaInfo data, boolean isAddPictureItem) {
            CardView rl_take_photos = (CardView) holder.itemView.findViewById(R.attr.rl_take_photos);
            rl_take_photos.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Theme.getColor(Theme.key_windowBackgroundGrayText)));
            ImageView iv_photo = (ImageView) holder.itemView.findViewById(R.attr.iv_photo);
            ViewGroup.LayoutParams lp = rl_take_photos.getLayoutParams();
            lp.width = ((this.screenWidth - AndroidUtilities.dp(30.0f)) - AndroidUtilities.dp(20.0f)) / 3;
            lp.height = lp.width;
            rl_take_photos.setLayoutParams(lp);
            if (isAddPictureItem) {
                iv_photo.setVisibility(8);
                return;
            }
            iv_photo.setVisibility(0);
            GlideUtils.getInstance().loadLocal(data.path, FcPublishActivity.this.mContext, iv_photo, R.drawable.shape_fc_default_pic_bg);
            iv_photo.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcPublishActivity$Adapter$D7tBHGTm7VNR08xdnSMGdfdGXrg
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$0$FcPublishActivity$Adapter(position, view);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$FcPublishActivity$Adapter(int position, View v) {
            if (FcPublishActivity.this.imageSelectorAlert == null) {
                FcPublishActivity.this.createChatAttachView();
            }
            FcPublishActivity.this.imageSelectorAlert.previewSelectedPhotos(position, FcPublishActivity.this.photoEntries);
        }
    }

    public static class Holder extends RecyclerView.ViewHolder {
        public Holder(View itemView) {
            super(itemView);
        }
    }

    public boolean isNetworkConnected(Context context) {
        if (context != null) {
            ConnectivityManager mConnectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            NetworkInfo mNetworkInfo = mConnectivityManager.getActiveNetworkInfo();
            if (mNetworkInfo != null) {
                return mNetworkInfo.isAvailable();
            }
            return false;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void readyUpload() throws JSONException {
        if (this.mbytAttachType == this.ATTACH_TYPE_VIDEO) {
            uploadSource(this.photoEntryVideo.path, this.mMapPhotos.get(this.photoEntryVideo.path));
            return;
        }
        KLog.d("-----------上" + this.mMapPhotos.size());
        this.photoList = new ArrayList<>();
        for (Map.Entry<String, String> entry : this.mMapPhotos.entrySet()) {
            KLog.e(TAG, "添加list == " + entry.getKey());
            this.photoList.add(entry);
        }
        if (this.photoList.size() > 0) {
            Map.Entry<String, String> entry2 = this.photoList.get(0);
            uploadSource(entry2.getKey(), entry2.getValue());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void uploadSource(final String sourcePath, final String thumbPath) throws JSONException {
        KLog.e(TAG, "上传 == " + sourcePath);
        uploadFile(sourcePath, new DataListener<BResponse<FcMediaResponseBean>>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.10
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcMediaResponseBean> result) {
                if (result != null && result.isState()) {
                    if (TextUtils.equals(sourcePath, thumbPath)) {
                        FcMediaBean mMediasBean = new FcMediaBean();
                        String servicePath = result.Data.getName();
                        mMediasBean.setSeq(0);
                        mMediasBean.setExt(3);
                        mMediasBean.setName(servicePath);
                        mMediasBean.setThum(servicePath);
                        FcPublishActivity.this.mMediasList.add(mMediasBean);
                        FcPublishActivity.this.sendDataToServer();
                        return;
                    }
                    FcMediaBean mMediasBean2 = new FcMediaBean();
                    String servicePath2 = result.Data.getName();
                    mMediasBean2.setName(servicePath2);
                    if (FcPublishActivity.this.mMapPhotos.size() == 1 && sourcePath.endsWith(".mp4")) {
                        mMediasBean2.setSeq(0);
                        mMediasBean2.setExt(2);
                        mMediasBean2.setWidth(FcPublishActivity.this.miVideoWidth);
                        mMediasBean2.setHeight(FcPublishActivity.this.miVideoHeight);
                    } else {
                        mMediasBean2.setExt(1);
                        mMediasBean2.setName(servicePath2);
                    }
                    FcPublishActivity.this.uploadThumb(thumbPath, mMediasBean2);
                    return;
                }
                FcToastUtils.show((CharSequence) LocaleController.getString("error_server_data", R.string.error_server_data));
                if (FcPublishActivity.this.progressDialog != null) {
                    FcPublishActivity.this.progressDialog.dismiss();
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcToastUtils.show((CharSequence) RxHelper.getInstance().getErrorInfo(throwable));
                if (FcPublishActivity.this.progressDialog != null) {
                    FcPublishActivity.this.progressDialog.dismiss();
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void uploadThumb(String thumb, final FcMediaBean mMediasBean) {
        uploadFile(thumb, new DataListener<BResponse<FcMediaResponseBean>>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.11
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<FcMediaResponseBean> result) throws JSONException {
                if (result != null && result.isState()) {
                    FcPublishActivity.access$1308(FcPublishActivity.this);
                    String servicePath = result.Data.getName();
                    mMediasBean.setThum(servicePath);
                    FcPublishActivity.this.mMediasList.add(mMediasBean);
                    if (FcPublishActivity.this.mMapPhotos.size() == FcPublishActivity.this.currentUploadIndex) {
                        FcPublishActivity.this.sendDataToServer();
                        return;
                    } else {
                        if (FcPublishActivity.this.photoList != null && FcPublishActivity.this.currentUploadIndex < FcPublishActivity.this.photoList.size() && FcPublishActivity.this.photoList.size() > 0) {
                            Map.Entry<String, String> entry = (Map.Entry) FcPublishActivity.this.photoList.get(FcPublishActivity.this.currentUploadIndex);
                            FcPublishActivity.this.uploadSource(entry.getKey(), entry.getValue());
                            return;
                        }
                        return;
                    }
                }
                FcToastUtils.show((CharSequence) LocaleController.getString("error_server_data", R.string.error_server_data));
                if (FcPublishActivity.this.progressDialog != null) {
                    FcPublishActivity.this.progressDialog.dismiss();
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcToastUtils.show((CharSequence) RxHelper.getInstance().getErrorInfo(throwable));
                if (FcPublishActivity.this.progressDialog != null) {
                    FcPublishActivity.this.progressDialog.dismiss();
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void getUploadUrlFailed(String msg) {
        super.getUploadUrlFailed(msg);
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null && alertDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onUploadFileError(String msg) {
        FcToastUtils.show((CharSequence) msg);
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null && alertDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
    }

    private void setTopicsInfo(TagFlowLayout viewTopics) {
        viewTopics.removeAllViews();
        viewTopics.setVisibility(0);
        TagAdapter<RespTopicBean.Item> tagAdapter = new TagAdapter<RespTopicBean.Item>(new ArrayList()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity.12
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter
            public View getView(FlowLayout parent, int position, RespTopicBean.Item value) {
                MryTextView tv = (MryTextView) LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_child_view_topics, (ViewGroup) null);
                MryRoundButtonDrawable bg = new MryRoundButtonDrawable();
                bg.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundGray)));
                bg.setIsRadiusAdjustBounds(true);
                bg.setStrokeWidth(0);
                tv.setBackground(bg);
                tv.setTextColor(Theme.key_windowBackgroundWhiteBlackText);
                SpannableStringBuilder stringBuilder = new SpannableStringBuilder(value.TopicName);
                stringBuilder.insert(0, (CharSequence) "# ");
                stringBuilder.setSpan(new ForegroundColorSpan(FcPublishActivity.this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), 0, 1, 18);
                tv.setText(stringBuilder);
                return tv;
            }
        };
        this.tagadapter = tagAdapter;
        viewTopics.setAdapter(tagAdapter);
    }
}
