package im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper;

import com.bjz.comm.net.bean.FcReplyBean;
import com.litesuits.orm.LiteOrm;
import com.litesuits.orm.db.assit.QueryBuilder;
import com.litesuits.orm.db.assit.WhereBuilder;
import com.litesuits.orm.db.model.ColumnsValue;
import com.litesuits.orm.db.model.ConflictAlgorithm;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.javaBean.fc.HomeFcListBean;
import im.uwrkaxlmjj.javaBean.fc.RecommendFcListBean;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class FcDBHelper {
    private LiteOrm fcLiteOrm;
    private static final String TAG = FcDBHelper.class.getSimpleName();
    private static FcDBHelper Instance = new FcDBHelper();

    private FcDBHelper() {
        if (this.fcLiteOrm == null) {
            synchronized (FcDBHelper.class) {
                if (this.fcLiteOrm == null) {
                    this.fcLiteOrm = LiteOrm.newCascadeInstance(ApplicationLoader.applicationContext, "User_Fc.db");
                }
            }
            this.fcLiteOrm.setDebugged(true);
        }
    }

    public static FcDBHelper getInstance() {
        return Instance;
    }

    public void init(ApplicationLoader applicationLoader) {
        if (this.fcLiteOrm == null) {
            synchronized (FcDBHelper.class) {
                if (this.fcLiteOrm == null) {
                    this.fcLiteOrm = LiteOrm.newCascadeInstance(applicationLoader, "User_Fc.db");
                }
            }
            this.fcLiteOrm.setDebugged(true);
        }
    }

    public <T> long insert(T t) {
        return this.fcLiteOrm.save(t);
    }

    public <T> void insertAll(List<T> list) {
        if (list != null && list.size() > 0) {
            this.fcLiteOrm.save((Collection) list);
        }
    }

    public <T> List<T> getQueryAll(Class<T> cla) {
        return this.fcLiteOrm.query(cla);
    }

    public <T> ArrayList getQueryByOrder(Class<T> cla) {
        QueryBuilder<T> mQueryBuilder = new QueryBuilder(cla).appendOrderDescBy("ForumID");
        return this.fcLiteOrm.query(mQueryBuilder);
    }

    public <T> List<T> getQueryByWhere(Class<T> cla, String field, String[] value) {
        return this.fcLiteOrm.query(new QueryBuilder(cla).where(field + "=?", value));
    }

    public <T> ArrayList<T> queryFcListByUserId(Class<T> cla, long userId) {
        QueryBuilder<T> mQueryBuilder = new QueryBuilder(cla).where("CreateBy = " + userId, new Object[0]).appendOrderDescBy("ForumID");
        return this.fcLiteOrm.query(mQueryBuilder);
    }

    public <T> T queryItemById(Class<T> cls, long j) {
        return (T) this.fcLiteOrm.queryById(j, cls);
    }

    public <T> List<T> getQueryByWhereLength(Class<T> cla, String field, String[] value, int start, int length) {
        return this.fcLiteOrm.query(new QueryBuilder(cla).where(field + "=?", value).limit(start, length));
    }

    public <T> void updateItemPermissionStatus(Class<T> cla, long forumId, int permission) {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("ForumID=?", Long.valueOf(forumId));
        HashMap<String, Object> replaceValue = new HashMap<>();
        replaceValue.put("Permission", Integer.valueOf(permission));
        this.fcLiteOrm.update(mQueryBuilder, new ColumnsValue(replaceValue), ConflictAlgorithm.Fail);
    }

    public <T> void updateItemFollowStatus(Class<T> cla, long userId, boolean isFollow) {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("CreateBy=?", Long.valueOf(userId));
        HashMap<String, Object> replaceValue = new HashMap<>();
        replaceValue.put("HasFollow", Boolean.valueOf(isFollow));
        this.fcLiteOrm.update(mQueryBuilder, new ColumnsValue(replaceValue), ConflictAlgorithm.Fail);
    }

    public <T> void updateItemLikeStatus(Class<T> cla, long forumId, boolean isLike, int ThumbUp) {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("ForumID=?", Long.valueOf(forumId));
        HashMap<String, Object> replaceValue = new HashMap<>();
        replaceValue.put("HasThumb", Boolean.valueOf(isLike));
        replaceValue.put("ThumbUp", Integer.valueOf(ThumbUp));
        this.fcLiteOrm.update(mQueryBuilder, new ColumnsValue(replaceValue), ConflictAlgorithm.Fail);
    }

    public <T> void updateItemReply(Class<T> cla, long forumId, FcReplyBean mFcReplyBean) {
        Object objQueryItemById = queryItemById(cla, forumId);
        if (objQueryItemById == null) {
            return;
        }
        if (objQueryItemById instanceof HomeFcListBean) {
            HomeFcListBean updateData = (HomeFcListBean) objQueryItemById;
            ArrayList<FcReplyBean> comments = updateData.getComments();
            if (comments != null) {
                comments.add(mFcReplyBean);
            }
            updateData.setCommentCount(updateData.getCommentCount() + 1);
            this.fcLiteOrm.save(updateData);
            return;
        }
        if (objQueryItemById instanceof RecommendFcListBean) {
            RecommendFcListBean updateData2 = (RecommendFcListBean) objQueryItemById;
            ArrayList<FcReplyBean> comments2 = updateData2.getComments();
            if (comments2 != null) {
                comments2.add(mFcReplyBean);
            }
            updateData2.setCommentCount(updateData2.getCommentCount() + 1);
            this.fcLiteOrm.save(updateData2);
            return;
        }
        if (objQueryItemById instanceof FollowedFcListBean) {
            FollowedFcListBean updateData3 = (FollowedFcListBean) objQueryItemById;
            ArrayList<FcReplyBean> comments3 = updateData3.getComments();
            if (comments3 != null) {
                comments3.add(mFcReplyBean);
            }
            updateData3.setCommentCount(updateData3.getCommentCount() + 1);
            this.fcLiteOrm.save(updateData3);
        }
    }

    public <T> void delete(T t) {
        this.fcLiteOrm.delete(t);
    }

    public <T> void deleteItemById(Class<T> cla, long id) throws JSONException {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("ForumID=?", Long.valueOf(id));
        int back = this.fcLiteOrm.delete(mQueryBuilder);
        KLog.d(TAG, "deleteItemById()-------删除结果" + back);
    }

    public <T> void deleteItemByUserId(Class<T> cla, long userId) throws JSONException {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("CreateBy=?", Long.valueOf(userId));
        int back = this.fcLiteOrm.delete(mQueryBuilder);
        KLog.d(TAG, "deleteItemById()-------删除结果" + back);
    }

    public <T> void deleteReply(Class<T> cla, long forumId, long commentID, int commentCount) throws JSONException {
        WhereBuilder mQueryBuilder = new WhereBuilder(cla).where("ForumID=?", Long.valueOf(forumId));
        HashMap<String, Object> replaceValue = new HashMap<>();
        replaceValue.put("CommentCount", Integer.valueOf(commentCount));
        this.fcLiteOrm.update(mQueryBuilder, new ColumnsValue(replaceValue), ConflictAlgorithm.Fail);
        int back1 = this.fcLiteOrm.delete(new WhereBuilder(FcReplyBean.class).where("CommentID = " + commentID, new Object[0]));
        KLog.d(TAG, "deleteReply()------------删除用户评论" + back1);
        int back2 = this.fcLiteOrm.delete(new WhereBuilder(FcReplyBean.class).where("SupID = " + commentID, new Object[0]));
        KLog.d(TAG, "deleteReply()------------删除用户评论" + back2);
    }

    public <T> void delete(Class<T> cla) {
        this.fcLiteOrm.delete((Class) cla);
    }

    public <T> void deleteList(List<T> list) {
        this.fcLiteOrm.delete((Collection) list);
    }

    public <T> void deleteAll(Class<T> var1) {
        this.fcLiteOrm.deleteAll(var1);
    }

    public void deleteDatabase() {
        this.fcLiteOrm.deleteDatabase();
    }
}
