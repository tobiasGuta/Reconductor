package domain

// PreparedSetOutputAuthorityMaxBytes bounds one provider attempt's configured
// prepared-set reservation and aggregate output authority. Aggregate unresolved
// store capacity remains a separate operator-configured limit.
const PreparedSetOutputAuthorityMaxBytes int64 = 8 * 1024 * 1024
