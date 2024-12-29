import { Module } from '@nestjs/common'

import { ProviderService } from './provider.service'

@Module({
	providers: [ProviderService]
})
export class ProviderModule {}
