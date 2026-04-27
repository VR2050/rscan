package com.bjz.comm.net.bean;

import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.enums.AssignType;
import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
@Table("mp_list_all")
public class MiniProgramBean implements Serializable {
    private String AppId;
    private String AppRouterPath;
    private int Classtify;
    private String CreateAt;
    private String CreateBy;
    private int DownloadCount;
    private String DownloadURL;
    private String FileName;
    private String FilePath;

    @PrimaryKey(AssignType.BY_MYSELF)
    private int ID;
    private String Introduction;
    private boolean IsNeedRqToken;
    private String Language;
    private String Logo;
    private String Name;
    private int Score;
    private int Size;
    private String Slogan;
    private int State;
    private int Version;
    private String VersionCreateAt;
    private DigitalTokenBean digitalTokenBean;

    public MiniProgramBean(int ID) {
        this.ID = ID;
    }

    public MiniProgramBean(int ID, boolean isNeedToken, String appRouterPath) {
        this.ID = ID;
        this.IsNeedRqToken = isNeedToken;
        this.AppRouterPath = appRouterPath;
    }

    public int getID() {
        return this.ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getName() {
        return this.Name;
    }

    public void setName(String Name) {
        this.Name = Name;
    }

    public int getClasstify() {
        return this.Classtify;
    }

    public void setClasstify(int Classtify) {
        this.Classtify = Classtify;
    }

    public String getCreateAt() {
        return this.CreateAt;
    }

    public void setCreateAt(String CreateAt) {
        this.CreateAt = CreateAt;
    }

    public String getCreateBy() {
        return this.CreateBy;
    }

    public void setCreateBy(String CreateBy) {
        this.CreateBy = CreateBy;
    }

    public String getLanguage() {
        return this.Language;
    }

    public void setLanguage(String Language) {
        this.Language = Language;
    }

    public int getScore() {
        return this.Score;
    }

    public void setScore(int Score) {
        this.Score = Score;
    }

    public int getState() {
        return this.State;
    }

    public void setState(int State) {
        this.State = State;
    }

    public int getVersion() {
        return this.Version;
    }

    public void setVersion(int Version) {
        this.Version = Version;
    }

    public int getSize() {
        return this.Size;
    }

    public void setSize(int Size) {
        this.Size = Size;
    }

    public String getDownloadURL() {
        return this.DownloadURL;
    }

    public void setDownloadURL(String DownloadURL) {
        this.DownloadURL = DownloadURL;
    }

    public int getDownloadCount() {
        return this.DownloadCount;
    }

    public void setDownloadCount(int DownloadCount) {
        this.DownloadCount = DownloadCount;
    }

    public String getIntroduction() {
        return this.Introduction;
    }

    public void setIntroduction(String Introduction) {
        this.Introduction = Introduction;
    }

    public String getSlogan() {
        return this.Slogan;
    }

    public void setSlogan(String Slogan) {
        this.Slogan = Slogan;
    }

    public String getLogo() {
        return this.Logo;
    }

    public void setLogo(String Logo) {
        this.Logo = Logo;
    }

    public String getVersionCreateAt() {
        return this.VersionCreateAt;
    }

    public void setVersionCreateAt(String VersionCreateAt) {
        this.VersionCreateAt = VersionCreateAt;
    }

    public String getFileName() {
        return this.FileName;
    }

    public void setFileName(String fileName) {
        this.FileName = fileName;
    }

    public String getAppId() {
        return this.AppId;
    }

    public void setAppId(String appId) {
        this.AppId = appId;
    }

    public String getFilePath() {
        return this.FilePath;
    }

    public void setFilePath(String filePath) {
        this.FilePath = filePath;
    }

    public boolean isNeedRqToken() {
        return this.IsNeedRqToken;
    }

    public void setNeedRqToken(boolean needRqToken) {
        this.IsNeedRqToken = needRqToken;
    }

    public String getAppRouterPath() {
        return this.AppRouterPath;
    }

    public void setAppRouterPath(String appRouterPath) {
        this.AppRouterPath = appRouterPath;
    }

    public DigitalTokenBean getDigitalTokenBean() {
        return this.digitalTokenBean;
    }

    public void setDigitalTokenBean(DigitalTokenBean digitalTokenBean) {
        this.digitalTokenBean = digitalTokenBean;
    }

    public String toString() {
        return "MiniProgramBean{ID=" + this.ID + ", Name='" + this.Name + "', Classtify=" + this.Classtify + ", CreateAt='" + this.CreateAt + "', CreateBy='" + this.CreateBy + "', Language='" + this.Language + "', Score=" + this.Score + ", State=" + this.State + ", Version=" + this.Version + ", Size=" + this.Size + ", DownloadURL='" + this.DownloadURL + "', DownloadCount=" + this.DownloadCount + ", Introduction='" + this.Introduction + "', Slogan='" + this.Slogan + "', Logo='" + this.Logo + "', VersionCreateAt='" + this.VersionCreateAt + "', FileName='" + this.FileName + "', AppId='" + this.AppId + "', FilePath='" + this.FilePath + "', IsNeedRqToken='" + this.IsNeedRqToken + "', AppRouterPath='" + this.AppRouterPath + "'}";
    }
}
