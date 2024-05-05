import mongoose from 'mongoose'

const activitySchema = mongoose.Schema({
    userId : {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    activityType: {
        type: String,
        enum: ["login", "logout"],
        required: true,
    },
    deviceInfo: {
        type: String,
        required: true,
    },
    timestamp: {
        type: Date,
        default: Date.now(),
    },
});

const Activity = mongoose.model('Activity', activitySchema);

export default Activity;