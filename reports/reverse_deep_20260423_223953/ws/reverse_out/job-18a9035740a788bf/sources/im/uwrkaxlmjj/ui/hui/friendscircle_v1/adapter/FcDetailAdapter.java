package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.app.Activity;
import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.cardview.widget.CardView;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.AvatarPhotoBean;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcMediaBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.TopicBean;
import com.bjz.comm.net.expandViewModel.StatusType;
import com.bjz.comm.net.utils.HttpUtils;
import com.preview.PhotoPreview;
import com.preview.interfaces.ImageLoader;
import com.preview.interfaces.OnLongClickListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcPhotosAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.decoration.GridSpaceItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FCLinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcClickSpanListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.ExpandableTextView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.FlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagFlowLayout;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextBuilder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcDetailAdapter extends BaseFcAdapter<FcReplyBean> {
    private static final int ITEM_TYPE_BOTTOM;
    private static final int ITEM_TYPE_REPLY;
    public static final int Index_child_reply_click_avatar;
    public static final int Index_child_reply_click_like;
    public static final int Index_click_comment;
    public static final int Index_click_comment_like;
    public static final int Index_click_forum_like;
    public static final int Index_click_load_more_like;
    public static final int Index_click_location;
    public static final int Index_click_more_reply;
    public static final int Index_download_photo;
    public static final int Index_download_video;
    private static int index;
    private static int itemType;
    private String TAG;
    private final int currentUserId;
    private FcDetailLikedUserAdapter fcLikedUserAdapter;
    private boolean isShowAtUser;
    private GridLayoutManager likeLayoutManager;
    private FcItemActionClickListener listener;
    private Activity mContext;
    private RespFcListBean mFcContentBean;
    private final int mGuid;
    private PhotoPreview photoPreview;
    private RelativeLayout rlLikeUsers;
    private RecyclerView rvLikeUsers;
    private final int screenWidth;
    private SpanCreateListener spanCreateListener;
    public static final int Index_click_avatar = 0;
    private static final int ITEM_TYPE_HEADER = 0;

    static {
        index = 0;
        int i = 0 + 1;
        index = i;
        int i2 = i + 1;
        index = i2;
        Index_download_photo = i;
        int i3 = i2 + 1;
        index = i3;
        Index_download_video = i2;
        int i4 = i3 + 1;
        index = i4;
        Index_click_forum_like = i3;
        int i5 = i4 + 1;
        index = i5;
        Index_click_comment_like = i4;
        int i6 = i5 + 1;
        index = i6;
        Index_click_comment = i5;
        int i7 = i6 + 1;
        index = i7;
        Index_click_more_reply = i6;
        int i8 = i7 + 1;
        index = i8;
        Index_click_location = i7;
        int i9 = i8 + 1;
        index = i9;
        Index_click_load_more_like = i8;
        int i10 = i9 + 1;
        index = i10;
        Index_child_reply_click_avatar = i9;
        index = i10 + 1;
        Index_child_reply_click_like = i10;
        itemType = 0;
        int i11 = 0 + 1;
        itemType = i11;
        int i12 = i11 + 1;
        itemType = i12;
        ITEM_TYPE_BOTTOM = i11;
        itemType = i12 + 1;
        ITEM_TYPE_REPLY = i12;
    }

    public FcDetailAdapter(Collection<FcReplyBean> collection, final Activity mContext, int guid, FcItemActionClickListener listener) {
        super(collection, R.layout.item_fc_detail_parent_reply);
        this.TAG = FcDetailAdapter.class.getSimpleName();
        this.isShowAtUser = false;
        this.spanCreateListener = new SpanCreateListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.16
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickAtUserSpan getCustomClickAtUserSpan(Context context, FCEntitysResponse FCEntitysResponse, int color, SpanAtUserCallBack spanClickCallBack) {
                return new FCClickAtUserSpan(FcDetailAdapter.this.mGuid, FCEntitysResponse, color, new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.16.1
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
                    public void onPresentFragment(BaseFragment baseFragment) {
                        if (FcDetailAdapter.this.listener != null && baseFragment != null) {
                            FcDetailAdapter.this.listener.onPresentFragment(baseFragment);
                        }
                    }
                });
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public ClickTopicSpan getCustomClickTopicSpan(Context context, TopicBean topicBean, int color, SpanTopicCallBack spanTopicCallBack) {
                return new FCClickTopicSpan(topicBean, color, spanTopicCallBack);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener
            public LinkSpan getCustomLinkSpan(Context context, String url, int color, SpanUrlCallBack spanUrlCallBack) {
                return new FCLinkSpan(context, url, color, spanUrlCallBack);
            }
        };
        this.mContext = mContext;
        this.mGuid = guid;
        this.listener = listener;
        PhotoPreview photoPreview = new PhotoPreview((FragmentActivity) mContext, false, new ImageLoader() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.1
            @Override // com.preview.interfaces.ImageLoader
            public void onLoadImage(int position, Object object, ImageView imageView) {
                KLog.d("-------大图-" + HttpUtils.getInstance().getDownloadFileUrl() + object);
                GlideUtils.getInstance().loadNOCentercrop(HttpUtils.getInstance().getDownloadFileUrl() + object, mContext, imageView, 0);
            }
        });
        this.photoPreview = photoPreview;
        photoPreview.setIndicatorType(0);
        this.photoPreview.setLongClickListener(new OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.2
            @Override // com.preview.interfaces.OnLongClickListener
            public void onLongClick(FrameLayout rootView, Object path, int position) {
                FcDetailAdapter.this.setAction(rootView, FcDetailAdapter.Index_download_photo, position, path);
            }
        });
        this.screenWidth = Util.getScreenWidth(mContext);
        this.currentUserId = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id;
    }

    public void setFcContentData(RespFcListBean mFcContentBean) {
        this.mFcContentBean = mFcContentBean;
        if (mFcContentBean != null) {
            this.isShowAtUser = mFcContentBean.isRecommend();
        }
    }

    public RespFcListBean getFcContentBean() {
        return this.mFcContentBean;
    }

    public void setFcLikeBeans(int pageNo, ArrayList<FcLikeBean> fcLikeBeans) {
        if (this.rlLikeUsers != null && this.rvLikeUsers != null) {
            if (fcLikeBeans != null && fcLikeBeans.size() > 0) {
                this.rlLikeUsers.setVisibility(0);
                if (this.fcLikedUserAdapter == null) {
                    setLikedUserView();
                }
                if (pageNo == 0) {
                    this.fcLikedUserAdapter.refresh(fcLikeBeans);
                    return;
                } else {
                    this.fcLikedUserAdapter.loadMore(fcLikeBeans);
                    return;
                }
            }
            this.rlLikeUsers.setVisibility(8);
        }
    }

    public FcDetailLikedUserAdapter getFcLikedUserAdapter() {
        return this.fcLikedUserAdapter;
    }

    public void doLikeUserChanged(FcLikeBean data, boolean isLike) {
        RelativeLayout relativeLayout = this.rlLikeUsers;
        if (relativeLayout == null || this.rvLikeUsers == null) {
            return;
        }
        if (isLike) {
            relativeLayout.setVisibility(0);
            FcDetailLikedUserAdapter fcDetailLikedUserAdapter = this.fcLikedUserAdapter;
            if (fcDetailLikedUserAdapter == null) {
                setLikedUserView();
            } else {
                fcDetailLikedUserAdapter.setThumbUp(true);
            }
            if (this.fcLikedUserAdapter.getDataList() != null) {
                this.fcLikedUserAdapter.getDataList().add(0, data);
                int size = this.fcLikedUserAdapter.getDataList().size();
                int thumbUp = this.fcLikedUserAdapter.getThumbUp();
                if (size >= thumbUp || (size % 8 != 0 && size % 8 != 1)) {
                    this.fcLikedUserAdapter.notifyItemInserted(0);
                    return;
                } else {
                    this.fcLikedUserAdapter.notifyDataSetChanged();
                    return;
                }
            }
            ArrayList arrayList = new ArrayList();
            arrayList.add(data);
            this.fcLikedUserAdapter.refresh(arrayList);
            return;
        }
        if (this.fcLikedUserAdapter != null && relativeLayout.getVisibility() == 0) {
            List<FcLikeBean> fcLikeBeans = this.fcLikedUserAdapter.getDataList();
            if (fcLikeBeans != null && fcLikeBeans.size() > 0 && this.likeLayoutManager != null) {
                int itemCount = fcLikeBeans.size();
                int i1 = 0;
                while (true) {
                    if (i1 >= itemCount) {
                        break;
                    }
                    View view = this.likeLayoutManager.findViewByPosition(i1);
                    if (view.getTag() == null || ((Integer) view.getTag()).intValue() != data.getCreateBy()) {
                        i1++;
                    } else {
                        this.fcLikedUserAdapter.getDataList().remove(i1);
                        this.fcLikedUserAdapter.setThumbUp(false);
                        int size2 = this.fcLikedUserAdapter.getDataList().size();
                        int thumbUp2 = this.fcLikedUserAdapter.getThumbUp();
                        if (size2 < thumbUp2 && (size2 % 8 == 0 || size2 % 8 == 7)) {
                            this.fcLikedUserAdapter.notifyDataSetChanged();
                        } else {
                            this.fcLikedUserAdapter.notifyItemRemoved(i1);
                            FcDetailLikedUserAdapter fcDetailLikedUserAdapter2 = this.fcLikedUserAdapter;
                            fcDetailLikedUserAdapter2.notifyItemRangeChanged(i1, fcDetailLikedUserAdapter2.getItemCount());
                        }
                    }
                }
            }
            if (this.fcLikedUserAdapter.getDataList().size() == 0) {
                this.rlLikeUsers.setVisibility(8);
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.mList.size();
    }

    public FcReplyBean getEndListId() {
        if (this.mList.size() == 0) {
            return null;
        }
        return (FcReplyBean) this.mList.get((this.mList.size() - 1) - getFooterSize());
    }

    public int getFooterSize() {
        FcReplyBean fcReplyBean;
        return (getDataList().size() <= 1 || (fcReplyBean = getDataList().get(getItemCount() - 1)) == null || fcReplyBean.getCommentID() != 0) ? 0 : 1;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        if (position == 0 && this.mFcContentBean != null) {
            return ITEM_TYPE_HEADER;
        }
        if (position == getItemCount() - 1 && ((FcReplyBean) this.mList.get(position)).getCommentID() == 0) {
            return ITEM_TYPE_BOTTOM;
        }
        return ITEM_TYPE_REPLY;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public SmartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (viewType == ITEM_TYPE_HEADER) {
            return new FcVideoViewHold(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_detail_header_content, parent, false), this.mListener);
        }
        if (viewType == ITEM_TYPE_BOTTOM) {
            return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.view_fc_footer, parent, false), this.mListener);
        }
        return new SmartViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_detail_parent_reply, parent, false), this.mListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder viewHolder, final FcReplyBean model, final int position) {
        LinearLayout rlChildReply;
        viewHolder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        if (getItemViewType(position) != ITEM_TYPE_HEADER) {
            if (getItemViewType(position) != ITEM_TYPE_BOTTOM) {
                View itemView = viewHolder.itemView;
                RichTextView txt_parent_comment = (RichTextView) itemView.findViewById(R.attr.txt_parent_comment);
                LinearLayout rlChildReply2 = (LinearLayout) itemView.findViewById(R.attr.rl_child_reply);
                if (!Theme.getCurrentTheme().isLight()) {
                    rlChildReply2.setBackground(ShapeUtils.create(Theme.getColor(Theme.key_windowBackgroundGray), AndroidUtilities.dp(4.0f)));
                }
                BackupImageView ivUserAvatar = (BackupImageView) itemView.findViewById(R.attr.iv_user_avatar);
                ivUserAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
                MryTextView tvUserName = (MryTextView) itemView.findViewById(R.attr.tv_user_name);
                MryTextView tvPublishTime = (MryTextView) itemView.findViewById(R.attr.tv_publish_time);
                final MryTextView btnLike = (MryTextView) itemView.findViewById(R.attr.btn_like);
                itemView.findViewById(R.attr.view_divider).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                bindUserInfo(model.getCreator(), model.getCreateAt(), ivUserAvatar, tvUserName, null, tvPublishTime, position);
                btnLike.setSelected(model.isHasThumb());
                btnLike.setText(model.getThumbUp() > 0 ? String.valueOf(model.getThumbUp()) : "0");
                btnLike.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.6
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        btnLike.setClickable(false);
                        FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_comment_like, position, model);
                    }
                });
                bindReplyView(model, txt_parent_comment, false, position, -1, itemView);
                ArrayList<FcReplyBean> childFcReplyBean = model.getSubComment();
                if (childFcReplyBean != null && childFcReplyBean.size() > 0) {
                    rlChildReply2.removeAllViews();
                    int i = 0;
                    while (true) {
                        if (i >= childFcReplyBean.size()) {
                            rlChildReply = rlChildReply2;
                            break;
                        }
                        if (i == 2) {
                            rlChildReply = rlChildReply2;
                            break;
                        }
                        RichTextView txt_comment = new RichTextView(this.mContext);
                        txt_comment.setGravity(16);
                        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, -2);
                        if (i != 0) {
                            layoutParams.topMargin = AndroidUtilities.dp(4.0f);
                        }
                        txt_comment.setLayoutParams(layoutParams);
                        txt_comment.setTextColor(this.mContext.getResources().getColor(R.color.black));
                        txt_comment.setTextSize(14.0f);
                        RichTextView richTextView = bindReplyView(childFcReplyBean.get(i), txt_comment, true, position, i, null);
                        rlChildReply2.addView(richTextView);
                        i++;
                    }
                    if (model.getSubComments() > 2) {
                        RichTextView txt_comment2 = new RichTextView(this.mContext);
                        txt_comment2.setGravity(16);
                        LinearLayout.LayoutParams layoutParams2 = new LinearLayout.LayoutParams(-1, -2);
                        layoutParams2.topMargin = AndroidUtilities.dp(4.0f);
                        txt_comment2.setLayoutParams(layoutParams2);
                        txt_comment2.setTextColor(this.mContext.getResources().getColor(R.color.color_FF7A8391));
                        txt_comment2.setTextSize(14.0f);
                        txt_comment2.setText(String.format("查看%d条回复>", Integer.valueOf(model.getSubComments())));
                        rlChildReply.addView(txt_comment2);
                        rlChildReply.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.7
                            @Override // android.view.View.OnClickListener
                            public void onClick(View v) {
                                FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_more_reply, position, model);
                            }
                        });
                    }
                    rlChildReply.setVisibility(0);
                    return;
                }
                if (rlChildReply2.getChildCount() > 0 && rlChildReply2.getVisibility() == 0) {
                    rlChildReply2.removeAllViews();
                    rlChildReply2.setVisibility(8);
                }
            }
        } else {
            View itemView2 = viewHolder.itemView;
            BackupImageView ivUserAvatar2 = (BackupImageView) itemView2.findViewById(R.attr.iv_user_avatar);
            ivUserAvatar2.setRoundRadius(AndroidUtilities.dp(5.0f));
            MryTextView tvUserName2 = (MryTextView) itemView2.findViewById(R.attr.tv_user_name);
            MryTextView tvPublishTime2 = (MryTextView) itemView2.findViewById(R.attr.tv_publish_time);
            MryTextView tvGender = (MryTextView) itemView2.findViewById(R.attr.tv_gender);
            TagFlowLayout viewTopics = (TagFlowLayout) itemView2.findViewById(R.attr.view_topics);
            MryTextView btnReply = (MryTextView) itemView2.findViewById(R.attr.btn_reply);
            final MryTextView btnLike2 = (MryTextView) itemView2.findViewById(R.attr.btn_like);
            ViewStub viewStubLocation = (ViewStub) itemView2.findViewById(R.attr.viewStub_location);
            this.rlLikeUsers = (RelativeLayout) itemView2.findViewById(R.attr.rl_like_users);
            itemView2.findViewById(R.attr.view_divider).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            itemView2.findViewById(R.attr.view_divider1).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            this.rvLikeUsers = (RecyclerView) itemView2.findViewById(R.attr.rv_like_users);
            bindUserInfo(this.mFcContentBean.getCreatorUser(), this.mFcContentBean.getCreateAt(), ivUserAvatar2, tvUserName2, tvGender, tvPublishTime2, position);
            setTextView(itemView2, this.mFcContentBean);
            CardView flMediaContainer = (CardView) itemView2.findViewById(R.attr.fl_media_container);
            RecyclerView rlFcDetailPhotos = (RecyclerView) itemView2.findViewById(R.attr.rv_photos);
            FcVideoPlayerView rlFcDetailVideo = (FcVideoPlayerView) itemView2.findViewById(R.attr.view_video);
            if (this.mFcContentBean.getMedias() != null && this.mFcContentBean.getMedias().size() > 0) {
                flMediaContainer.setVisibility(0);
                FcMediaBean fcMediaBean = this.mFcContentBean.getMedias().get(0);
                if (fcMediaBean.getExt() == 1 || fcMediaBean.getExt() == 3) {
                    flMediaContainer.setBackground(ShapeUtils.create(Theme.getColor(Theme.key_windowBackgroundWhite), 8.0f));
                    setPhotosView(rlFcDetailPhotos, this.mFcContentBean.getMedias());
                    rlFcDetailPhotos.setVisibility(0);
                } else if (fcMediaBean.getExt() == 2) {
                    itemView2.setTag(HttpUtils.getInstance().getDownloadFileUrl() + fcMediaBean.getName());
                    setVideoView(rlFcDetailVideo, fcMediaBean, position);
                    rlFcDetailVideo.setVisibility(0);
                }
            } else {
                flMediaContainer.setVisibility(8);
            }
            setTopicsInfo(viewTopics, this.mFcContentBean.getTopic());
            btnLike2.setSelected(this.mFcContentBean.isHasThumb());
            btnLike2.setText(this.mFcContentBean.getThumbUp() > 0 ? String.valueOf(this.mFcContentBean.getThumbUp()) : "0");
            btnLike2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.3
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    btnLike2.setClickable(false);
                    FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_forum_like, position, FcDetailAdapter.this.mFcContentBean);
                }
            });
            btnReply.setText(this.mFcContentBean.getCommentCount() > 0 ? String.valueOf(this.mFcContentBean.getCommentCount()) : "0");
            btnReply.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.4
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_comment, position, model);
                }
            });
            String name = this.mFcContentBean.getLocationName();
            String city = this.mFcContentBean.getLocationCity();
            MryTextView tvFcDetailLocation = null;
            if (!TextUtils.isEmpty(name)) {
                if (!TextUtils.isEmpty(city) && !TextUtils.equals(name, city)) {
                    name = city.replace("市", "") + "·" + name;
                }
                if (viewStubLocation != null && viewStubLocation.getParent() != null) {
                    View inflate = viewStubLocation.inflate();
                    tvFcDetailLocation = (MryTextView) inflate.findViewById(R.attr.tv_fc_detail_location);
                } else {
                    tvFcDetailLocation = (MryTextView) itemView2.findViewById(R.attr.tv_fc_detail_location);
                }
            }
            if (tvFcDetailLocation != null) {
                tvFcDetailLocation.setVisibility(TextUtils.isEmpty(name) ? 8 : 0);
                tvFcDetailLocation.setText(TextUtils.isEmpty(name) ? "" : name);
                tvFcDetailLocation.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.5
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_location, position, FcDetailAdapter.this.mFcContentBean);
                    }
                });
            }
        }
    }

    private void bindUserInfo(final FcUserInfoBean fcUserInfoBean, long createAt, BackupImageView ivUserAvatar, MryTextView tvUserName, MryTextView tvGender, MryTextView tvPublishTime, final int position) {
        if (fcUserInfoBean != null) {
            if (tvGender != null) {
                if (fcUserInfoBean.getSex() != 0) {
                    tvGender.setSelected(fcUserInfoBean.getSex() == 1);
                    if (fcUserInfoBean.getBirthday() > 0) {
                        Date date = new Date(((long) fcUserInfoBean.getBirthday()) * 1000);
                        int ageByBirthday = TimeUtils.getAgeByBirthday(date);
                        tvGender.setText(ageByBirthday > 0 ? String.valueOf(ageByBirthday) : "");
                        tvGender.setCompoundDrawablePadding(ageByBirthday > 0 ? AndroidUtilities.dp(2.0f) : 0);
                    } else {
                        tvGender.setText("");
                        tvGender.setCompoundDrawablePadding(0);
                    }
                    tvGender.setVisibility(0);
                } else {
                    tvGender.setVisibility(8);
                }
            }
            AvatarPhotoBean avatarPhotoBean = fcUserInfoBean.getPhoto();
            if (avatarPhotoBean != null) {
                int photoSize = avatarPhotoBean.getSmallPhotoSize();
                int localId = avatarPhotoBean.getSmallLocalId();
                long volumeId = avatarPhotoBean.getSmallVolumeId();
                if (photoSize != 0 && volumeId != 0 && avatarPhotoBean.getAccess_hash() != 0) {
                    TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
                    inputPeer.user_id = fcUserInfoBean.getUserId();
                    inputPeer.access_hash = fcUserInfoBean.getAccessHash();
                    ImageLocation imageLocation = new ImageLocation();
                    imageLocation.dc_id = 2;
                    imageLocation.photoPeer = inputPeer;
                    imageLocation.location = new TLRPC.TL_fileLocationToBeDeprecated();
                    imageLocation.location.local_id = localId;
                    imageLocation.location.volume_id = volumeId;
                    AvatarDrawable drawable = new AvatarDrawable();
                    ivUserAvatar.setImage(imageLocation, "40_40", drawable, inputPeer);
                }
            }
            tvUserName.setText(StringUtils.handleTextName(ContactsController.formatName(fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName()), 12));
            tvPublishTime.setText(TimeUtils.fcFormat2Date(createAt));
            tvPublishTime.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
            ivUserAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.8
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_avatar, position, fcUserInfoBean);
                }
            });
            tvUserName.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.9
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    FcDetailAdapter.this.setAction(v, FcDetailAdapter.Index_click_avatar, position, fcUserInfoBean);
                }
            });
        }
    }

    private void setTextView(View itemView, RespFcListBean model) {
        ExpandableTextView tvContent = (ExpandableTextView) itemView.findViewById(R.attr.view_fc_text);
        tvContent.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        if (!TextUtils.isEmpty(model.getContent())) {
            tvContent.bind(model);
            tvContent.setEntitys(model.getEntitys());
            tvContent.setContent(model.getContent());
            tvContent.setLinkClickListener(new FcClickSpanListener(this.mContext, this.mGuid, this.listener));
            model.setStatusType(StatusType.STATUS_CONTRACT);
            tvContent.setVisibility(0);
            return;
        }
        tvContent.setVisibility(8);
    }

    private void setPhotosView(final RecyclerView rlFcDetailPhotos, ArrayList<FcMediaBean> medias) {
        if (rlFcDetailPhotos != null) {
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) rlFcDetailPhotos.getLayoutParams();
            if (medias.size() == 1) {
                lp.width = (((int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f))) / 3) * 2;
                rlFcDetailPhotos.setLayoutManager(new LinearLayoutManager(this.mContext));
            } else if (medias.size() == 2 || medias.size() == 4) {
                rlFcDetailPhotos.setLayoutManager(new GridLayoutManager(this.mContext, 2));
                lp.width = (((int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f))) / 3) * 2;
                if (rlFcDetailPhotos.getItemDecorationCount() == 0) {
                    rlFcDetailPhotos.addItemDecoration(new GridSpaceItemDecoration(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), false));
                }
            } else {
                rlFcDetailPhotos.setLayoutManager(new GridLayoutManager(this.mContext, 3));
                lp.width = (int) (this.screenWidth - Util.dp2px(this.mContext, 40.0f));
                if (rlFcDetailPhotos.getItemDecorationCount() == 0) {
                    rlFcDetailPhotos.addItemDecoration(new GridSpaceItemDecoration(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), false));
                }
            }
            lp.height = -2;
            rlFcDetailPhotos.setLayoutParams(lp);
            rlFcDetailPhotos.setAdapter(new FcPhotosAdapter(medias, this.mContext, R.layout.item_friends_circle_img, this.screenWidth, new FcPhotosAdapter.OnPicClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.-$$Lambda$FcDetailAdapter$CE-PhL2snCTXmFCyiRiHrrC7dW0
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcPhotosAdapter.OnPicClickListener
                public final void onPicClick(View view, List list, int i) {
                    this.f$0.lambda$setPhotosView$0$FcDetailAdapter(rlFcDetailPhotos, view, list, i);
                }
            }, true));
        }
    }

    public /* synthetic */ void lambda$setPhotosView$0$FcDetailAdapter(RecyclerView rlFcDetailPhotos, View view, List dualist, int position1) {
        PhotoPreview photoPreview = this.photoPreview;
        if (photoPreview != null) {
            photoPreview.show(rlFcDetailPhotos, position1, (List<?>) dualist);
        }
    }

    private void setVideoView(final FcVideoPlayerView rlFcDetailVideo, final FcMediaBean fcMediaBean, final int position) {
        if (rlFcDetailVideo != null) {
            String strThumb = HttpUtils.getInstance().getDownloadFileUrl() + fcMediaBean.getThum();
            rlFcDetailVideo.bind(HttpUtils.getInstance().getDownloadVideoFileUrl() + fcMediaBean.getName(), "");
            rlFcDetailVideo.getThumbImageView().setScaleType(ImageView.ScaleType.CENTER_CROP);
            float Ratio = (float) (((double) fcMediaBean.getWidth()) / fcMediaBean.getHeight());
            FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) rlFcDetailVideo.getLayoutParams();
            if (Ratio > 1.0f) {
                params.width = AndroidUtilities.dp(240.0f);
                params.height = AndroidUtilities.dp(140.0f);
            } else {
                params.width = AndroidUtilities.dp(240.0f);
                params.height = AndroidUtilities.dp(320.0f);
            }
            rlFcDetailVideo.setLayoutParams(params);
            rlFcDetailVideo.setRatio(Ratio);
            GlideUtils.getInstance().load(strThumb, this.mContext, rlFcDetailVideo.getThumbImageView(), R.drawable.shape_fc_default_pic_bg);
            rlFcDetailVideo.setListener(new FcVideoPlayerView.OnClickVideoContainerListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.10
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView.OnClickVideoContainerListener
                public void onLongClick() {
                    FcDetailAdapter.this.setAction(rlFcDetailVideo, FcDetailAdapter.Index_download_video, position, fcMediaBean.getName());
                }
            });
        }
    }

    private void setTopicsInfo(TagFlowLayout viewTopics, ArrayList<TopicBean> topic) {
        viewTopics.removeAllViews();
        if (topic != null && topic.size() > 0) {
            viewTopics.setVisibility(0);
            viewTopics.setAdapter(new TagAdapter<TopicBean>(topic) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.11
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter
                public View getView(FlowLayout parent, int position, TopicBean topicBean) {
                    MryTextView tv = (MryTextView) LayoutInflater.from(parent.getContext()).inflate(R.layout.item_fc_child_view_topics, (ViewGroup) null);
                    if (!TextUtils.isEmpty(topicBean.getTopicName())) {
                        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(topicBean.getTopicName());
                        stringBuilder.insert(0, (CharSequence) "# ");
                        stringBuilder.setSpan(new ForegroundColorSpan(FcDetailAdapter.this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), 0, 1, 18);
                        tv.setText(stringBuilder);
                    }
                    return tv;
                }
            });
        } else {
            viewTopics.setVisibility(8);
        }
    }

    private void setLikedUserView() {
        if (this.rvLikeUsers != null) {
            GridLayoutManager gridLayoutManager = new GridLayoutManager(this.mContext, 8);
            this.likeLayoutManager = gridLayoutManager;
            this.rvLikeUsers.setLayoutManager(gridLayoutManager);
            FcDetailLikedUserAdapter fcDetailLikedUserAdapter = new FcDetailLikedUserAdapter(this.mContext, new ArrayList(), R.layout.item_fc_detail_liked_user, true, this.mFcContentBean.getThumbUp(), this.listener);
            this.fcLikedUserAdapter = fcDetailLikedUserAdapter;
            this.rvLikeUsers.setAdapter(fcDetailLikedUserAdapter);
        }
    }

    private RichTextView bindReplyView(final FcReplyBean model, RichTextView txt_comment, boolean isChild, final int parentPosition, final int childPosition, View itemView) {
        RichTextView txt_comment2;
        String commentUserName;
        if (txt_comment != null) {
            txt_comment2 = txt_comment;
        } else {
            RichTextView txt_comment3 = new RichTextView(this.mContext);
            txt_comment3.setLayoutParams(new RelativeLayout.LayoutParams(-1, -2));
            txt_comment2 = txt_comment3;
        }
        txt_comment2.setClickable(false);
        txt_comment2.setLongClickable(false);
        txt_comment2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        RichTextBuilder richTextBuilder = new RichTextBuilder(this.mContext);
        richTextBuilder.setContent(model.getContent() == null ? "" : model.getContent()).setLinkColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setAtColor(ContextCompat.getColor(this.mContext, R.color.color_FF09A4C9)).setTextView(txt_comment2).setListUser(model.getEntitys()).setNeedUrl(true).setSpanCreateListener(this.spanCreateListener).build();
        FcUserInfoBean creator = model.getCreator();
        if (creator == null) {
            commentUserName = "";
        } else {
            String commentUserName2 = StringUtils.handleTextName(ContactsController.formatName(creator.getFirstName(), creator.getLastName()), 12);
            if (isChild) {
                SpannableStringBuilder headerStr = new SpannableStringBuilder();
                if (model.getReplayID() == this.mFcContentBean.getForumID()) {
                    headerStr.append((CharSequence) commentUserName2);
                    headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF7A8391)), 0, commentUserName2.length(), 34);
                    headerStr.append((CharSequence) ": ");
                } else {
                    headerStr.append((CharSequence) commentUserName2);
                    headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF7A8391)), 0, commentUserName2.length(), 34);
                    headerStr.append((CharSequence) " ");
                    String reply = LocaleController.getString("Reply", R.string.Reply);
                    headerStr.append((CharSequence) reply);
                    headerStr.append((CharSequence) " ");
                    headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_FF2ECEFD)), commentUserName2.length(), headerStr.length(), 33);
                    int StartIndex = headerStr.length();
                    FcUserInfoBean replayUser = model.getReplayUser();
                    String replyUserName = StringUtils.handleTextName(ContactsController.formatName(replayUser.getFirstName(), replayUser.getLastName()), 12);
                    headerStr.append((CharSequence) replyUserName);
                    headerStr.setSpan(new ForegroundColorSpan(this.mContext.getResources().getColor(R.color.color_999999)), StartIndex, headerStr.length(), 33);
                    headerStr.append((CharSequence) " : ");
                }
                CharSequence content = txt_comment2.getText();
                if (!TextUtils.isEmpty(headerStr) && !TextUtils.isEmpty(content)) {
                    SpannableStringBuilder stringBuilder = new SpannableStringBuilder(content);
                    stringBuilder.insert(0, (CharSequence) headerStr, 0, headerStr.length());
                    txt_comment2.setText(stringBuilder);
                }
            }
            commentUserName = commentUserName2;
        }
        final String finalCommentUserName = commentUserName;
        if (itemView != null) {
            itemView.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.12
                @Override // android.view.View.OnLongClickListener
                public boolean onLongClick(View v) {
                    FcDetailAdapter.this.listener.onReplyClick(v, TextUtils.equals(finalCommentUserName, "") ? "" : finalCommentUserName, FcDetailAdapter.this.mFcContentBean, parentPosition, childPosition, true);
                    return true;
                }
            });
            itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.13
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (FcDetailAdapter.this.currentUserId != 0 && FcDetailAdapter.this.currentUserId != model.getCreateBy() && FcDetailAdapter.this.listener != null) {
                        FcDetailAdapter.this.listener.onReplyClick(v, TextUtils.equals(finalCommentUserName, "") ? "" : finalCommentUserName, FcDetailAdapter.this.mFcContentBean, parentPosition, childPosition, false);
                    }
                }
            });
        }
        txt_comment2.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.14
            @Override // android.view.View.OnLongClickListener
            public boolean onLongClick(View v) {
                FcDetailAdapter.this.listener.onReplyClick(v, TextUtils.equals(finalCommentUserName, "") ? "" : finalCommentUserName, FcDetailAdapter.this.mFcContentBean, parentPosition, childPosition, true);
                return true;
            }
        });
        txt_comment2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDetailAdapter.15
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcDetailAdapter.this.currentUserId != 0 && FcDetailAdapter.this.currentUserId != model.getCreateBy() && FcDetailAdapter.this.listener != null) {
                    FcDetailAdapter.this.listener.onReplyClick(v, TextUtils.equals(finalCommentUserName, "") ? "" : finalCommentUserName, FcDetailAdapter.this.mFcContentBean, parentPosition, childPosition, false);
                }
            }
        });
        return txt_comment2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setAction(View v, int index2, int position, Object o) {
        FcItemActionClickListener fcItemActionClickListener = this.listener;
        if (fcItemActionClickListener != null) {
            fcItemActionClickListener.onAction(v, index2, position, o);
        }
    }

    public void setShowAtUser(boolean showAtUser) {
        this.isShowAtUser = showAtUser;
    }
}
