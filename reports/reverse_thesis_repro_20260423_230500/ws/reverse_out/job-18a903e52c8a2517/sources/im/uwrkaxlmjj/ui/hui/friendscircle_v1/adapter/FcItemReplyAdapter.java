package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.content.Context;
import android.text.Html;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.view.View;
import androidx.core.content.ContextCompat;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RespFcListBean;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcItemActionClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.DataFormatUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.LinkMovementClickMethod;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextBuilder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView;
import java.util.Collection;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcItemReplyAdapter extends BaseFcAdapter<FcReplyBean> {
    private long currentForumID;
    private final int currentUserId;
    private int itemPosition;
    private final FcItemActionClickListener listener;
    private Context mContext;
    private RespFcListBean model;
    private final SpanCreateListener spanCreateListener;

    public FcItemReplyAdapter(Context context, Collection<FcReplyBean> collection, int layoutId, boolean flag, long currentForumID, int itemPosition, RespFcListBean model, FcItemActionClickListener listener, SpanCreateListener spanCreateListener) {
        super(collection, layoutId);
        this.mContext = context;
        this.flag = flag;
        this.currentForumID = currentForumID;
        this.itemPosition = itemPosition;
        this.model = model;
        this.listener = listener;
        this.spanCreateListener = spanCreateListener;
        this.currentUserId = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.BaseFcAdapter
    public void onBindViewHolder(SmartViewHolder abrItem, FcReplyBean model, final int position) {
        abrItem.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        RichTextView txt_comment = (RichTextView) abrItem.itemView.findViewById(R.attr.txt_comment);
        if (model != null) {
            final String userNameByid = DataFormatUtils.getUserNameByid(model.getCreateBy());
            Spanned userName = model.getReplayID() == this.currentForumID ? Html.fromHtml(this.mContext.getResources().getString(R.string.fc_detail_child_comment2, userNameByid)) : Html.fromHtml(this.mContext.getResources().getString(R.string.fc_detail_child_comment3, userNameByid, DataFormatUtils.getUserNameByid(model.getReplayUID())));
            RichTextBuilder richTextBuilder = new RichTextBuilder(this.mContext);
            richTextBuilder.setContent(model.getContent() == null ? "" : model.getContent()).setLinkColor(ContextCompat.getColor(this.mContext, R.color.color_5080B5)).setTextView(txt_comment).setListUser(model.getEntitys()).setNeedUrl(true).setSpanCreateListener(this.spanCreateListener).build();
            CharSequence content = txt_comment.getText();
            if (!TextUtils.isEmpty(userName) && !TextUtils.isEmpty(content)) {
                SpannableStringBuilder stringBuilder = new SpannableStringBuilder(content);
                stringBuilder.insert(0, (CharSequence) userName, 0, userName.length());
                txt_comment.setText(stringBuilder);
            }
            txt_comment.setMovementMethod(LinkMovementClickMethod.getInstance());
            txt_comment.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcItemReplyAdapter.1
                @Override // android.view.View.OnLongClickListener
                public boolean onLongClick(View v) {
                    FcItemReplyAdapter.this.listener.onReplyClick(v, TextUtils.equals(userNameByid, "") ? "" : userNameByid, FcItemReplyAdapter.this.model, FcItemReplyAdapter.this.itemPosition, position, true);
                    return true;
                }
            });
            int i = this.currentUserId;
            if (i != 0 && i != model.getForumUser()) {
                txt_comment.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcItemReplyAdapter.2
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        if (FcItemReplyAdapter.this.listener != null) {
                            FcItemReplyAdapter.this.listener.onReplyClick(v, TextUtils.equals(userNameByid, "") ? "" : userNameByid, FcItemReplyAdapter.this.model, FcItemReplyAdapter.this.itemPosition, position, false);
                        }
                    }
                });
            }
        }
    }
}
