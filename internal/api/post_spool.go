package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const postSpoolBufferSize = 32 * 1024

func spoolPostFile(ctx context.Context, upload *postUpload, manager SpoolManager, limit int64) (postValidatedFile, error) {
	if ctx == nil || upload == nil || manager == nil || upload.fileRead == nil || upload.wire == nil || upload.reader == nil {
		return postValidatedFile{}, ErrPostFormMalformed
	}
	if err := ctx.Err(); err != nil {
		return postValidatedFile{}, ErrStreamingCanceled
	}
	maximum := minPostLimit(upload.maximumFileSize, upload.wire.fileLimit)
	if limit <= 0 {
		limit = postDefaultFileLimit
	}
	maximum = minPostLimit(maximum, limit, postDefaultFileLimit)
	if upload.limitSnapshot.Global > 0 {
		maximum = minPostLimit(maximum, upload.limitSnapshot.Global)
	}
	if maximum < 0 {
		return postValidatedFile{}, ErrPostEntityTooLarge
	}
	reservation, err := manager.Acquire(ctx, 0, maximum)
	if err != nil {
		return postValidatedFile{}, classifyPostSpoolAcquire(err)
	}
	directory := ""
	if shared, ok := manager.(*spoolManager); ok {
		directory = shared.tempDirectory()
	}
	file, err := streamingSpoolOps.createTemp(directory, "s3gw-post-plain-*")
	if err != nil {
		reservation.Release()
		return postValidatedFile{}, fmt.Errorf("%w: create POST plaintext spool", ErrStreamingSpool)
	}
	path := file.Name()
	cleanup := func() {
		_ = streamingSpoolOps.close(file)
		_ = streamingSpoolOps.remove(path)
		reservation.Release()
	}
	if err := streamingSpoolOps.chmod(file, 0600); err != nil {
		cleanup()
		return postValidatedFile{}, fmt.Errorf("%w: secure POST plaintext spool", ErrStreamingSpool)
	}
	checksum, err := upload.checksum.newSet()
	if err != nil {
		cleanup()
		return postValidatedFile{}, err
	}
	buffer := make([]byte, postSpoolBufferSize)
	var length int64
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return postValidatedFile{}, ErrStreamingCanceled
		}
		if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
			cleanup()
			return postValidatedFile{}, ErrRequestExpired
		}
		remaining := maximum - length
		readBuffer := buffer
		if remaining < int64(len(readBuffer)) {
			readBuffer = readBuffer[:remaining+1]
		}
		n, readErr := streamingSpoolOps.readRequestBody(upload.fileRead, readBuffer)
		if err := ctx.Err(); err != nil {
			cleanup()
			return postValidatedFile{}, ErrStreamingCanceled
		}
		if readErr != nil && readErr != io.EOF && (errors.Is(readErr, ErrStreamingCanceled) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded)) {
			cleanup()
			return postValidatedFile{}, ErrStreamingCanceled
		}
		if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
			cleanup()
			return postValidatedFile{}, ErrRequestExpired
		}
		if n > 0 {
			if int64(n) > remaining {
				cleanup()
				return postValidatedFile{}, ErrPostEntityTooLarge
			}
			if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
				cleanup()
				return postValidatedFile{}, ErrRequestExpired
			}
			if err := reservation.Grow(int64(n)); err != nil {
				cleanup()
				return postValidatedFile{}, classifyPostSpoolAcquire(err)
			}
			written, writeErr := streamingSpoolOps.write(file, readBuffer[:n])
			if writeErr != nil || written != n {
				cleanup()
				return postValidatedFile{}, fmt.Errorf("%w: write POST plaintext spool", ErrStreamingSpool)
			}
			if _, hashErr := checksum.Write(readBuffer[:n]); hashErr != nil {
				cleanup()
				return postValidatedFile{}, fmt.Errorf("%w: hash POST plaintext", ErrStreamingSpool)
			}
			length += int64(n)
		}
		if readErr != nil {
			if readErr != io.EOF {
				cleanup()
				if errors.Is(readErr, ErrStreamingCanceled) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					return postValidatedFile{}, ErrStreamingCanceled
				}
				if errors.Is(readErr, ErrPostEntityTooLarge) || upload.wire.tooLarge {
					return postValidatedFile{}, ErrPostEntityTooLarge
				}
				if errors.Is(readErr, ErrPostFormMalformed) {
					return postValidatedFile{}, ErrPostFormMalformed
				}
				return postValidatedFile{}, ErrPostIncompleteBody
			}
			break
		}
		if n == 0 {
			cleanup()
			return postValidatedFile{}, ErrPostIncompleteBody
		}
	}
	if err := upload.Finish(); err != nil {
		cleanup()
		return postValidatedFile{}, err
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return postValidatedFile{}, ErrStreamingCanceled
	}
	if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
		cleanup()
		return postValidatedFile{}, ErrRequestExpired
	}
	if length < upload.minimumFileSize {
		cleanup()
		return postValidatedFile{}, ErrPostEntityTooSmall
	}
	md5Hex, responseChecksums, err := checksum.validate()
	if err != nil {
		cleanup()
		return postValidatedFile{}, err
	}
	if _, err := streamingSpoolOps.seek(file, 0, io.SeekStart); err != nil {
		cleanup()
		return postValidatedFile{}, fmt.Errorf("%w: rewind POST plaintext spool", ErrStreamingSpool)
	}
	body := &verifiedAWSFile{File: file, length: length, path: path, reservation: reservation}
	upload.body = body
	return postValidatedFile{body: body, length: length, md5Hex: md5Hex, responseChecksums: responseChecksums}, nil
}

func spoolPostCiphertext(ctx context.Context, reader io.Reader, manager SpoolManager) (verifiedAWSBody, error) {
	return spoolPostCiphertextDeadline(ctx, reader, manager, time.Time{})
}

func spoolPostCiphertextLimit(ctx context.Context, reader io.Reader, manager SpoolManager, limit int64) (verifiedAWSBody, error) {
	return spoolPostCiphertextUntil(ctx, reader, manager, limit, time.Time{})
}

func spoolPostCiphertextDeadline(ctx context.Context, reader io.Reader, manager SpoolManager, deadline time.Time) (verifiedAWSBody, error) {
	return spoolPostCiphertextUntil(ctx, reader, manager, 5<<30, deadline)
}

func spoolPostCiphertextUntil(ctx context.Context, reader io.Reader, manager SpoolManager, limit int64, deadline time.Time) (verifiedAWSBody, error) {
	if ctx == nil || reader == nil || manager == nil {
		return nil, ErrPostFormMalformed
	}
	if limit < 0 {
		return nil, ErrPostEntityTooLarge
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrStreamingCanceled
	}
	reservation, err := manager.Acquire(ctx, 0, limit)
	if err != nil {
		return nil, classifyPostSpoolAcquire(err)
	}
	directory := ""
	if shared, ok := manager.(*spoolManager); ok {
		directory = shared.tempDirectory()
	}
	file, err := streamingSpoolOps.createTemp(directory, "s3gw-post-cipher-*")
	if err != nil {
		reservation.Release()
		return nil, fmt.Errorf("%w: create POST ciphertext spool", ErrStreamingSpool)
	}
	path := file.Name()
	cleanup := func() {
		_ = streamingSpoolOps.close(file)
		_ = streamingSpoolOps.remove(path)
		reservation.Release()
	}
	if err := streamingSpoolOps.chmod(file, 0600); err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: secure POST ciphertext spool", ErrStreamingSpool)
	}
	buffer := make([]byte, postSpoolBufferSize)
	var length int64
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, ErrStreamingCanceled
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			cleanup()
			return nil, ErrRequestExpired
		}
		remaining := limit - length
		readBuffer := buffer
		if remaining < int64(len(readBuffer)) {
			readBuffer = readBuffer[:remaining+1]
		}
		n, readErr := streamingSpoolOps.readRequestBody(reader, readBuffer)
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, ErrStreamingCanceled
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			cleanup()
			return nil, ErrRequestExpired
		}
		if readErr != nil && readErr != io.EOF && (errors.Is(readErr, ErrStreamingCanceled) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded)) {
			cleanup()
			return nil, ErrStreamingCanceled
		}
		if n > 0 {
			if int64(n) > remaining {
				cleanup()
				return nil, ErrPostEntityTooLarge
			}
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				cleanup()
				return nil, ErrRequestExpired
			}
			if err := reservation.Grow(int64(n)); err != nil {
				cleanup()
				return nil, classifyPostSpoolAcquire(err)
			}
			written, writeErr := streamingSpoolOps.write(file, readBuffer[:n])
			if writeErr != nil || written != n {
				cleanup()
				return nil, fmt.Errorf("%w: write POST ciphertext spool", ErrStreamingSpool)
			}
			length += int64(n)
		}
		if readErr != nil {
			if readErr != io.EOF {
				cleanup()
				if errors.Is(readErr, ErrStreamingCanceled) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					return nil, ErrStreamingCanceled
				}
				return nil, ErrStreamingSpool
			}
			break
		}
		if n == 0 {
			cleanup()
			return nil, ErrStreamingSpool
		}
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return nil, ErrStreamingCanceled
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		cleanup()
		return nil, ErrRequestExpired
	}
	if _, err := streamingSpoolOps.seek(file, 0, io.SeekStart); err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: rewind POST ciphertext spool", ErrStreamingSpool)
	}
	return &verifiedAWSFile{File: file, length: length, path: path, reservation: reservation}, nil
}

func classifyPostSpoolAcquire(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrStreamingCanceled
	}
	return err
}

func minPostLimit(values ...int64) int64 {
	if len(values) == 0 {
		return 0
	}
	result := values[0]
	for _, value := range values[1:] {
		if value < result {
			result = value
		}
	}
	return result
}
