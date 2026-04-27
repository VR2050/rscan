package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class ResponseFcAlbumlistBean extends RecycleGridBean implements Serializable {
    private long CreateTime;
    private String FileName;
    private int FileSize;
    private int ForumID;
    private int ID;
    private int Index;
    private int PicHeight;
    private int PicWidth;
    private String Region;
    private String Thum;
    private int ThumSize;
    private String ThumbKeyHash;
    private String URL;
    private String URLKeyHash;
    private int URLType;
    private int VideoDuration;
    private int VideoHeight;
    private int VideoWidth;

    public int getID() {
        return this.ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public int getForumID() {
        return this.ForumID;
    }

    public void setForumID(int ForumID) {
        this.ForumID = ForumID;
    }

    public int getIndex() {
        return this.Index;
    }

    public void setIndex(int Index) {
        this.Index = Index;
    }

    public String getURL() {
        return this.URL;
    }

    public void setURL(String URL) {
        this.URL = URL;
    }

    public int getURLType() {
        return this.URLType;
    }

    public void setURLType(int URLType) {
        this.URLType = URLType;
    }

    public String getThum() {
        return this.Thum;
    }

    public void setThum(String Thum) {
        this.Thum = Thum;
    }

    public String getRegion() {
        return this.Region;
    }

    public void setRegion(String Region) {
        this.Region = Region;
    }

    public int getFileSize() {
        return this.FileSize;
    }

    public void setFileSize(int FileSize) {
        this.FileSize = FileSize;
    }

    public String getFileName() {
        return this.FileName;
    }

    public void setFileName(String FileName) {
        this.FileName = FileName;
    }

    public int getThumSize() {
        return this.ThumSize;
    }

    public void setThumSize(int ThumSize) {
        this.ThumSize = ThumSize;
    }

    public long getCreateTime() {
        return this.CreateTime;
    }

    public void setCreateTime(long CreateTime) {
        this.CreateTime = CreateTime;
    }

    public String getURLKeyHash() {
        return this.URLKeyHash;
    }

    public void setURLKeyHash(String URLKeyHash) {
        this.URLKeyHash = URLKeyHash;
    }

    public String getThumbKeyHash() {
        return this.ThumbKeyHash;
    }

    public void setThumbKeyHash(String ThumbKeyHash) {
        this.ThumbKeyHash = ThumbKeyHash;
    }

    public int getPicHeight() {
        return this.PicHeight;
    }

    public void setPicHeight(int PicHeight) {
        this.PicHeight = PicHeight;
    }

    public int getPicWidth() {
        return this.PicWidth;
    }

    public void setPicWidth(int PicWidth) {
        this.PicWidth = PicWidth;
    }

    public int getVideoDuration() {
        return this.VideoDuration;
    }

    public void setVideoDuration(int VideoDuration) {
        this.VideoDuration = VideoDuration;
    }

    public int getVideoHeight() {
        return this.VideoHeight;
    }

    public void setVideoHeight(int VideoHeight) {
        this.VideoHeight = VideoHeight;
    }

    public int getVideoWidth() {
        return this.VideoWidth;
    }

    public void setVideoWidth(int VideoWidth) {
        this.VideoWidth = VideoWidth;
    }

    public String toString() {
        return "ResponseFcAlbumlistBean{ID=" + this.ID + ", ForumID=" + this.ForumID + ", Index=" + this.Index + ", URL='" + this.URL + "', URLType=" + this.URLType + ", Thum='" + this.Thum + "', Region='" + this.Region + "', FileSize=" + this.FileSize + ", FileName='" + this.FileName + "', ThumSize=" + this.ThumSize + ", CreateTime=" + this.CreateTime + ", URLKeyHash='" + this.URLKeyHash + "', ThumbKeyHash='" + this.ThumbKeyHash + "', PicHeight=" + this.PicHeight + ", PicWidth=" + this.PicWidth + ", VideoDuration=" + this.VideoDuration + ", VideoHeight=" + this.VideoHeight + ", VideoWidth=" + this.VideoWidth + '}';
    }
}
