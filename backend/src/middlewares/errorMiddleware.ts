import express, { Request, Response, NextFunction } from 'express';

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  const raw = String(err.message || 'Internal Server Error');
  const [possibleCode, ...detailParts] = raw.split(':');
  const knownCode = /^[A-Z][A-Z0-9_]+$/.test(possibleCode) ? possibleCode : 'INTERNAL_ERROR';
  const status = knownCode === 'CURRENT_SBOM_NOT_FOUND' ? 404
    : knownCode === 'DEPENDENCY_FILES_NOT_FOUND' ? 422
      : knownCode === 'SOURCE_CLONE_FAILED' || knownCode === 'SYFT_ANALYSIS_FAILED' ? 502
        : 500;
  res.status(status).json({
    success: false,
    code: knownCode,
    message: detailParts.length ? detailParts.join(':').trim() : raw,
    detail: raw,
  });
};
